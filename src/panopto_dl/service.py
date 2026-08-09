"""Application orchestration across profiles, state, auth, planning, and downloads."""

from __future__ import annotations

import platform
import shutil
import sqlite3
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from threading import Event
from typing import Any
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo

from .browser import AuthResult, BrowserSession, BrowserSessionBoundary, browser_available
from .config import ConfigManager, ProfileConfig, ProfilePaths
from .database import ArtifactWrite, Database, DatabaseError, RecordNotFoundError
from .domain import (
    ArtifactKind,
    AttemptOutcome,
    DownloadPlan,
    MediaPolicy,
    PlanApplicationStatus,
    PlanItem,
    Session,
    SessionState,
    Source,
    utc_now,
)
from .errors import (
    AppError,
    AuthenticationError,
    LocalIOError,
    PolicyError,
    UsageError,
)
from .filesystem import (
    ensure_no_symlink_components,
    ensure_within_root,
    free_bytes,
    require_free_space,
    sha256_file,
    verify_media,
)
from .output import OperationResult
from .panopto import (
    DownloadResult,
    FormatSummary,
    PanoptoClient,
    PanoptoSession,
    ProgressEvent,
)
from .planner import (
    PlanCandidate,
    build_download_plan,
    plan_to_public_dict,
    session_output_directory,
)
from .security import canonical_uuid, redact_text, validate_allowed_url

_TERMINAL_MEDIA_STATES = frozenset({SessionState.COMPLETE, SessionState.NEEDS_COMPOSITE})
_MEDIA_SUFFIXES = frozenset(
    {".aac", ".flac", ".m4a", ".mkv", ".mov", ".mp3", ".mp4", ".ogg", ".opus", ".wav", ".webm"}
)


@dataclass(frozen=True, slots=True)
class _ItemOutcome:
    session_id: str
    state: SessionState
    output_path: Path
    artifacts: tuple[dict[str, object], ...] = ()
    error: AppError | None = None
    authentication_failed: bool = False
    not_ready: bool = False

    def public(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "session_id": self.session_id,
            "state": self.state.value,
            "output_path": str(self.output_path),
            "artifacts": list(self.artifacts),
        }
        if self.error is not None:
            payload["error"] = {
                "code": self.error.code,
                "message": redact_text(self.error.message),
                "retryable": self.error.retryable,
            }
        return payload


@dataclass(slots=True)
class AppService:
    """Profile-scoped use cases with all bearer state kept behind boundaries."""

    profile: ProfileConfig
    profile_paths: ProfilePaths
    database: Database
    browser: BrowserSessionBoundary
    progress: Callable[[str], None]
    client_factory: Callable[..., PanoptoClient] = PanoptoClient
    sleeper: Callable[[float], None] = time.sleep

    @classmethod
    def open(
        cls,
        profile_name: str,
        manager: ConfigManager,
        progress: Callable[[str], None] | None = None,
    ) -> AppService:
        profile = manager.get_profile(profile_name)
        profile_paths = manager.paths.profile(profile.name)
        profile_paths.ensure()
        database = Database.open(profile_paths.database)
        browser = BrowserSession(
            profile.site_url,
            profile_paths.browser,
            browser_executable=profile.browser_executable,
            browser_channel=profile.browser_channel,
        )
        return cls(profile, profile_paths, database, browser, progress or (lambda _: None))

    # Authentication

    def auth_login(self, timeout: int) -> dict[str, object]:
        with self.profile_paths.lock():
            result = self.browser.login(timeout_seconds=timeout)
        if not result.authenticated:
            raise AuthenticationError("Authentication was not completed before the login timeout")
        return {"authentication": _public_auth(result)}

    def auth_status(self) -> dict[str, object]:
        result = self.browser.status()
        if not result.authenticated:
            raise AuthenticationError()
        return {"authentication": _public_auth(result)}

    def auth_logout(self) -> dict[str, object]:
        with self.profile_paths.lock():
            result = self.browser.logout()
        return {"authentication": _public_auth(result)}

    # Read-only remote discovery. SQLite cache writes remain concurrent under WAL.

    def discover_folders(self, url: str | None) -> dict[str, object]:
        with self.browser.cookies_file(headless=True) as cookie_file:
            client = self._client(cookie_file)
            folders = client.discover_folders(url)
        return {
            "folder_count": len(folders),
            "folders": [_json_safe(folder.as_dict()) for folder in folders],
        }

    def discover_sessions(self, folder: str) -> dict[str, object]:
        source = self._source_if_registered(folder)
        selector = source.folder_id if source is not None else folder
        with self.browser.cookies_file(headless=True) as cookie_file:
            client = self._client(cookie_file)
            remote_sessions = client.discover_sessions(selector)
        sessions = [self._persist_remote_session(item, source) for item in remote_sessions]
        return {
            "selector": source.alias if source is not None else _stable_selector(selector),
            "session_count": len(sessions),
            "sessions": [self._public_session(item) for item in sessions],
        }

    def inspect(self, target: str) -> dict[str, object]:
        with self.browser.cookies_file(headless=True) as cookie_file:
            remote = self._client(cookie_file).inspect(target)
        stored = self._persist_remote_session(remote, None)
        return {"session": self._public_session(stored, remote)}

    # Registered source policy

    def source_add(
        self,
        folder: str,
        *,
        alias: str,
        auto_sync: bool,
        not_before: datetime | None,
    ) -> dict[str, object]:
        folder_id = _folder_identifier(folder, self.profile.site_url)
        cutoff = (
            _profile_datetime(not_before, self.profile) if not_before is not None else utc_now()
        )
        try:
            with self.profile_paths.lock():
                source = self.database.add_source(
                    folder_id,
                    alias,
                    auto_sync=auto_sync,
                    not_before=cutoff,
                )
        except DatabaseError as exc:
            raise UsageError(str(exc), code="SOURCE_CONFLICT") from exc
        return {"source": _public_source(source)}

    def source_list(self) -> dict[str, object]:
        sources = self.database.list_sources()
        return {"source_count": len(sources), "sources": [_public_source(item) for item in sources]}

    def source_remove(self, selector: str) -> dict[str, object]:
        source = self._source(selector)
        with self.profile_paths.lock():
            removed = self.database.remove_source(source.id)
        return {"source": _public_source(removed)}

    # Immutable planning

    def create_plan(
        self,
        *,
        sources: Sequence[str],
        sessions: Sequence[str],
        backfill: str | None,
        since: datetime | None,
        last: int | None,
        media_policy: MediaPolicy | None,
        refresh: bool = False,
    ) -> dict[str, object]:
        plan = self._create_plan(
            sources=sources,
            sessions=sessions,
            backfill=backfill,
            since=since,
            last=last,
            media_policy=media_policy,
            refresh=refresh,
        )
        return plan_to_public_dict(plan)

    def _create_plan(
        self,
        *,
        sources: Sequence[str],
        sessions: Sequence[str],
        backfill: str | None,
        since: datetime | None,
        last: int | None,
        media_policy: MediaPolicy | None,
        refresh: bool,
        allow_empty: bool = False,
    ) -> DownloadPlan:
        _validate_history_options(backfill, since, last)
        selected_sources = [self._source(item) for item in sources]
        if not selected_sources and not sessions:
            selected_sources = list(self.database.list_sources())
        if not selected_sources and not sessions:
            raise UsageError(
                "No registered source or one-off session was selected", code="PLAN_EMPTY"
            )

        policy = media_policy or self.profile.media_policy
        candidates: dict[str, PlanCandidate] = {}
        source_by_id = {source.id: source for source in selected_sources}
        cutoff = _profile_datetime(since, self.profile) if since is not None else None

        with self.browser.cookies_file(headless=True) as cookie_file:
            client = self._client(cookie_file)
            for source in selected_sources:
                self.progress(f"Discovering {source.alias}")
                for remote in client.discover_sessions(source.folder_id):
                    stored = self._persist_remote_session(remote, source)
                    if not _selected_by_history(stored, source, backfill, cutoff, last):
                        continue
                    candidate = self._candidate(stored, source.id, source.alias, refresh)
                    if candidate is not None:
                        candidates[stored.session_id] = candidate

            for target in sessions:
                remote = client.inspect(target)
                stored = self._persist_remote_session(remote, None)
                estimate = _policy_estimate(remote, policy)
                if stored.estimated_bytes != estimate:
                    stored = self.database.upsert_session(
                        stored.model_copy(update={"estimated_bytes": estimate})
                    )
                candidate = self._candidate(stored, None, "one-off", refresh)
                if candidate is not None:
                    candidates[stored.session_id] = candidate

            ordered = list(candidates.values())
            if last is not None:
                ordered = sorted(
                    ordered,
                    key=lambda candidate: (
                        candidate.session.recorded_at or datetime.min.replace(tzinfo=UTC)
                    ),
                    reverse=True,
                )[:last]
            if len(ordered) > self.profile.limits.max_sessions_per_run:
                raise PolicyError(
                    "The plan exceeds the profile session limit",
                    code="SESSION_LIMIT_EXCEEDED",
                    planned_sessions=len(ordered),
                    max_sessions=self.profile.limits.max_sessions_per_run,
                )

            hydrated: list[PlanCandidate] = []
            for candidate in ordered:
                if candidate.source_id is None:
                    hydrated.append(candidate)
                    continue
                remote = client.inspect(candidate.session.session_id)
                source = source_by_id[candidate.source_id]
                stored = self._persist_remote_session(remote, source)
                estimate = _policy_estimate(remote, policy)
                if stored.estimated_bytes != estimate:
                    stored = self.database.upsert_session(
                        stored.model_copy(update={"estimated_bytes": estimate}),
                        source_id=source.id,
                    )
                refreshed = self._candidate(stored, source.id, source.alias, refresh)
                if refreshed is not None:
                    hydrated.append(refreshed)
            ordered = hydrated

        plan = build_download_plan(
            profile_name=self.profile.name,
            config_fingerprint=self.profile.fingerprint(),
            output_root=self.profile.output_root,
            timezone_name=self.profile.timezone,
            media_policy=policy,
            candidates=ordered,
            max_sessions=self.profile.limits.max_sessions_per_run,
            max_estimated_bytes=self.profile.limits.max_estimated_bytes_per_run,
            allow_empty=allow_empty,
        )
        return self.database.save_plan(plan)

    def _candidate(
        self,
        session: Session,
        source_id: int | None,
        source_alias: str,
        refresh: bool,
    ) -> PlanCandidate | None:
        if session.state is SessionState.NOT_READY:
            return None
        if session.state in _TERMINAL_MEDIA_STATES and not refresh:
            return None

        override = session.output_path
        if session.state in _TERMINAL_MEDIA_STATES:
            base = override or session_output_directory(
                root=self.profile.output_root,
                source_alias=source_alias,
                session=session,
                timezone_name=self.profile.timezone,
            )
            if base.suffix:
                base = base.parent
            existing_revisions = [
                artifact.revision for artifact in self.database.list_artifacts(session.session_id)
            ]
            revision = max(existing_revisions, default=1) + 1
            override = ensure_within_root(base / f"revision-{revision}", self.profile.output_root)
        return PlanCandidate(session, source_id, source_alias, override)

    # Applying and synchronization

    def apply_plan(self, plan_id: str) -> OperationResult:
        with self.profile_paths.lock():
            return self._apply_plan_locked(plan_id)

    def _apply_plan_locked(self, plan_id: str) -> OperationResult:
        fingerprint = self.profile.fingerprint()
        plan = self.database.validate_plan(plan_id, fingerprint)
        self._preflight(plan)
        self.database.begin_plan_application(plan.plan_id, fingerprint)
        try:
            outcomes = self._execute_plan(plan)
        except KeyboardInterrupt:
            self._recover_downloading(plan)
            self.database.finish_plan_application(plan.plan_id, PlanApplicationStatus.INTERRUPTED)
            raise
        except Exception:
            self._recover_downloading(plan)
            self.database.finish_plan_application(plan.plan_id, PlanApplicationStatus.ERROR)
            raise

        hard_failures = [
            outcome for outcome in outcomes if outcome.error is not None and not outcome.not_ready
        ]
        completed = [
            outcome
            for outcome in outcomes
            if outcome.state in _TERMINAL_MEDIA_STATES and outcome.error is None
        ]
        not_ready = [outcome for outcome in outcomes if outcome.not_ready]

        if hard_failures and not completed:
            self.database.finish_plan_application(plan.plan_id, PlanApplicationStatus.ERROR)
            error = hard_failures[0].error
            assert error is not None
            raise error

        partial = bool(hard_failures)
        self.database.finish_plan_application(
            plan.plan_id,
            PlanApplicationStatus.PARTIAL if partial else PlanApplicationStatus.SUCCESS,
        )
        result = {
            "plan_id": plan.plan_id,
            "summary": {
                "total": len(outcomes),
                "complete": len(completed),
                "not_ready": len(not_ready),
                "failed": len(hard_failures),
            },
            "items": [outcome.public() for outcome in outcomes],
        }
        warnings = tuple(
            f"{outcome.session_id}: {outcome.error.code}"
            for outcome in hard_failures
            if outcome.error is not None
        )
        return OperationResult(result=result, warnings=warnings, partial=partial)

    def _preflight(self, plan: DownloadPlan) -> None:
        if len(plan.items) > self.profile.limits.max_sessions_per_run:
            raise PolicyError(
                "The plan exceeds the current session limit", code="SESSION_LIMIT_EXCEEDED"
            )
        known_bytes = sum(item.estimated_bytes or 0 for item in plan.items)
        if known_bytes > self.profile.limits.max_estimated_bytes_per_run:
            raise PolicyError("The plan exceeds the current byte limit", code="BYTE_LIMIT_EXCEEDED")
        require_free_space(
            self.profile.output_root,
            self.profile.limits.free_space_reserve_bytes + known_bytes,
        )
        for item in plan.items:
            ensure_no_symlink_components(item.output_path, self.profile.output_root)
            ensure_no_symlink_components(
                item.output_path.with_name(f"{item.output_path.name}.part"),
                self.profile.output_root,
            )
            ensure_within_root(item.output_path, self.profile.output_root)
            if item.source_id is not None:
                try:
                    self.database.get_source(item.source_id)
                except RecordNotFoundError as error:
                    raise PolicyError(
                        "A source was removed after this plan was created",
                        code="PLAN_SOURCE_CHANGED",
                    ) from error
            session = self.database.get_session(item.session_id)
            if item.output_path.exists() and session.output_path is None:
                raise PolicyError(
                    "The approved output directory already exists",
                    code="OUTPUT_EXISTS",
                )
            if session.state in _TERMINAL_MEDIA_STATES:
                revision = _revision_number(item.output_path)
                existing_revisions = [
                    artifact.revision for artifact in self.database.list_artifacts(item.session_id)
                ]
                expected_revision = max(existing_revisions, default=1) + 1
                if revision != expected_revision:
                    raise PolicyError(
                        "The approved media revision is no longer current",
                        code="PLAN_STALE",
                        session_id=item.session_id,
                    )

    def _execute_plan(self, plan: DownloadPlan) -> list[_ItemOutcome]:
        pending = list(plan.items)
        final: dict[str, _ItemOutcome] = {}
        for authentication_round in range(3):
            if not pending:
                break
            if authentication_round:
                self.progress("Refreshing the authenticated Panopto session")
            with self.browser.cookies_file(headless=True) as cookie_file:
                round_outcomes = self._execute_round(plan, pending, cookie_file)
            pending = []
            for outcome in round_outcomes:
                if outcome.authentication_failed and authentication_round < 2:
                    pending.append(_item_by_id(plan.items, outcome.session_id))
                else:
                    if outcome.authentication_failed:
                        stored = self.database.get_session(outcome.session_id)
                        if stored.state is SessionState.DOWNLOADING:
                            self.database.set_session_state(
                                outcome.session_id, SessionState.RETRYABLE_FAILED
                            )
                    final[outcome.session_id] = outcome
        return [final[item.session_id] for item in plan.items]

    def _recover_downloading(self, plan: DownloadPlan) -> None:
        for item in plan.items:
            stored = self.database.get_session(item.session_id)
            if stored.state is SessionState.DOWNLOADING:
                self.database.set_session_state(item.session_id, SessionState.RETRYABLE_FAILED)

    def _execute_round(
        self,
        plan: DownloadPlan,
        items: Sequence[PlanItem],
        cookie_file: Path,
    ) -> list[_ItemOutcome]:
        outcomes: dict[str, _ItemOutcome] = {}
        workers = min(self.profile.limits.max_media_jobs, max(1, len(items)))
        if workers == 1:
            return [self._download_item(plan, item, cookie_file) for item in items]
        cancelled = Event()
        executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="panopto-dl")
        futures: dict[Future[_ItemOutcome], PlanItem] = {}
        try:
            futures = {
                executor.submit(self._download_item, plan, item, cookie_file, cancelled): item
                for item in items
            }
            for future in as_completed(futures):
                outcome = future.result()
                outcomes[outcome.session_id] = outcome
        except KeyboardInterrupt:
            cancelled.set()
            for future in futures:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
            raise
        except BaseException:
            cancelled.set()
            for future in futures:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
            raise
        else:
            executor.shutdown(wait=True)
        return [outcomes[item.session_id] for item in items]

    def _download_item(
        self,
        plan: DownloadPlan,
        item: PlanItem,
        cookie_file: Path,
        cancelled: Event | None = None,
    ) -> _ItemOutcome:
        if cancelled is not None and cancelled.is_set():
            raise KeyboardInterrupt
        session = self.database.get_session(item.session_id)
        refresh = session.state in _TERMINAL_MEDIA_STATES and _is_revision_path(item.output_path)
        if not refresh:
            session = self._prepare_download_state(session, item, plan.media_policy)
        require_free_space(item.output_path.parent, self.profile.limits.free_space_reserve_bytes)

        last_error: AppError | None = None
        for retry_index in range(3):
            attempt = self.database.start_attempt(session.session_id, plan_id=plan.plan_id)
            try:
                self.progress(f"Downloading {session.session_id} (attempt {retry_index + 1}/3)")
                client = self._client(cookie_file)
                staging_directory = ensure_within_root(
                    item.output_path.with_name(f"{item.output_path.name}.part"),
                    self.profile.output_root,
                )
                result = client.download(
                    session.session_id,
                    staging_directory,
                    media_profile=plan.media_policy,
                    progress_hook=self._disk_progress_hook(staging_directory, cancelled),
                )
                if cancelled is not None and cancelled.is_set():
                    raise KeyboardInterrupt
                artifacts = self._validate_commit_and_record(
                    result,
                    item.output_path,
                    refresh,
                    attempt.attempt_id,
                )
                return _ItemOutcome(
                    session.session_id,
                    result.state,
                    item.output_path,
                    tuple(artifacts),
                )
            except KeyboardInterrupt:
                self.database.finish_attempt(
                    attempt.attempt_id,
                    AttemptOutcome.INTERRUPTED,
                    error_code="INTERRUPTED",
                    safe_error="Operation interrupted",
                )
                if not refresh:
                    self.database.set_session_state(
                        session.session_id, SessionState.RETRYABLE_FAILED
                    )
                raise
            except AuthenticationError as error:
                self.database.finish_attempt(
                    attempt.attempt_id,
                    AttemptOutcome.RETRYABLE_FAILED,
                    error_code=error.code,
                    safe_error=redact_text(error.message),
                )
                return _ItemOutcome(
                    session.session_id,
                    SessionState.RETRYABLE_FAILED,
                    item.output_path,
                    error=error,
                    authentication_failed=True,
                )
            except (DatabaseError, sqlite3.Error):
                local_error = LocalIOError(
                    "Validated download state could not be committed",
                    code="DATABASE_ERROR",
                    retryable=True,
                )
                self.database.finish_attempt(
                    attempt.attempt_id,
                    AttemptOutcome.RETRYABLE_FAILED,
                    error_code=local_error.code,
                    safe_error=local_error.message,
                )
                if not refresh:
                    self.database.set_session_state(
                        session.session_id, SessionState.RETRYABLE_FAILED
                    )
                return _ItemOutcome(
                    session.session_id,
                    SessionState.RETRYABLE_FAILED,
                    item.output_path,
                    error=local_error,
                )
            except OSError:
                local_error = LocalIOError("A local download file operation failed", retryable=True)
                self.database.finish_attempt(
                    attempt.attempt_id,
                    AttemptOutcome.RETRYABLE_FAILED,
                    error_code=local_error.code,
                    safe_error=local_error.message,
                )
                if not refresh:
                    self.database.set_session_state(
                        session.session_id, SessionState.RETRYABLE_FAILED
                    )
                return _ItemOutcome(
                    session.session_id,
                    SessionState.RETRYABLE_FAILED,
                    item.output_path,
                    error=local_error,
                )
            except AppError as error:
                last_error = error
                not_ready = error.code == "NOT_READY"
                outcome = (
                    AttemptOutcome.RETRYABLE_FAILED
                    if error.retryable or isinstance(error, LocalIOError)
                    else AttemptOutcome.PERMANENT_FAILED
                )
                self.database.finish_attempt(
                    attempt.attempt_id,
                    outcome,
                    error_code=error.code,
                    safe_error=redact_text(error.message),
                )
                if not_ready:
                    if not refresh:
                        self.database.set_session_state(session.session_id, SessionState.NOT_READY)
                    return _ItemOutcome(
                        session.session_id,
                        SessionState.NOT_READY,
                        item.output_path,
                        error=error,
                        not_ready=True,
                    )
                if error.retryable and retry_index < 2:
                    self.sleeper(min(4.0, float(2**retry_index)))
                    continue
                final_state = (
                    SessionState.RETRYABLE_FAILED
                    if error.retryable or isinstance(error, LocalIOError)
                    else SessionState.PERMANENT_FAILED
                )
                if not refresh:
                    self.database.set_session_state(session.session_id, final_state)
                return _ItemOutcome(
                    session.session_id,
                    final_state,
                    item.output_path,
                    error=error,
                )
            except Exception:
                self.database.finish_attempt(
                    attempt.attempt_id,
                    AttemptOutcome.RETRYABLE_FAILED,
                    error_code="INTERNAL_ERROR",
                    safe_error="Unexpected internal download failure",
                )
                if not refresh:
                    self.database.set_session_state(
                        session.session_id, SessionState.RETRYABLE_FAILED
                    )
                raise

        assert last_error is not None
        return _ItemOutcome(
            session.session_id,
            SessionState.RETRYABLE_FAILED,
            item.output_path,
            error=last_error,
        )

    def _prepare_download_state(
        self, session: Session, item: PlanItem, media_policy: MediaPolicy
    ) -> Session:
        current = session
        if current.state is SessionState.DOWNLOADING:
            current = self.database.set_session_state(
                current.session_id, SessionState.RETRYABLE_FAILED
            )
        if current.state is not SessionState.PLANNED:
            current = self.database.set_session_state(
                current.session_id,
                SessionState.PLANNED,
                output_path=item.output_path,
                media_policy=media_policy,
            )
        return self.database.set_session_state(
            current.session_id,
            SessionState.DOWNLOADING,
            output_path=item.output_path,
            media_policy=media_policy,
        )

    def _validate_commit_and_record(
        self,
        result: DownloadResult,
        destination: Path,
        refresh: bool,
        attempt_id: int,
    ) -> list[dict[str, object]]:
        existing = self.database.list_artifacts(result.session.session_id)
        revision = (
            max((artifact.revision for artifact in existing), default=0) + 1 if refresh else 1
        )
        prepared: list[tuple[Path, Path, ArtifactKind, int, str]] = []
        for artifact_path in result.artifacts:
            ensure_no_symlink_components(artifact_path, self.profile.output_root)
            if artifact_path.is_symlink():
                raise PolicyError(
                    "Downloaded artifacts must not be symbolic links",
                    code="OUTPUT_SYMLINK_DENIED",
                )
            staged_path = ensure_within_root(artifact_path, self.profile.output_root)
            if not staged_path.is_file():
                raise LocalIOError(
                    "A reported download artifact is missing", code="ARTIFACT_MISSING"
                )
            kind = _artifact_kind(staged_path)
            if kind is ArtifactKind.MEDIA:
                verify_media(staged_path)
            digest = sha256_file(staged_path)
            size = staged_path.stat().st_size
            final_path = ensure_within_root(
                destination / staged_path.name, self.profile.output_root
            )
            prepared.append((staged_path, final_path, kind, size, digest))
        if not prepared:
            raise LocalIOError("The download produced no artifacts", code="ARTIFACT_MISSING")

        expected_staged = {item[0] for item in prepared}
        unexpected = [
            item
            for item in result.destination.iterdir()
            if item.is_file() and item not in expected_staged
        ]
        if unexpected:
            raise LocalIOError(
                "The resumable staging directory still contains partial files",
                code="INCOMPLETE_STAGING",
                retryable=True,
            )

        ensure_no_symlink_components(destination, self.profile.output_root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            for staged_path, final_path, _kind, _size, digest in prepared:
                if not final_path.is_file() or sha256_file(final_path) != digest:
                    raise PolicyError(
                        "A different artifact already exists at the approved output path",
                        code="OUTPUT_EXISTS",
                    )
                staged_path.unlink()
            result.destination.rmdir()
        else:
            result.destination.replace(destination)

        writes = tuple(
            ArtifactWrite(kind, final_path, size, revision, digest)
            for _staged_path, final_path, kind, size, digest in prepared
        )
        self.database.commit_download(
            attempt_id=attempt_id,
            session_id=result.session.session_id,
            artifacts=writes,
            target_state=None if refresh else result.state,
            output_path=destination,
            media_policy=result.media_policy,
        )

        public: list[dict[str, object]] = []
        for _staged_path, final_path, kind, size, digest in prepared:
            public.append(
                {
                    "kind": kind.value,
                    "path": str(final_path),
                    "size_bytes": size,
                    "sha256": digest,
                    "revision": revision,
                }
            )
        return public

    def _disk_progress_hook(
        self, destination: Path, cancelled: Event | None = None
    ) -> Callable[[ProgressEvent], None]:
        def monitor(_: ProgressEvent) -> None:
            if cancelled is not None and cancelled.is_set():
                raise KeyboardInterrupt
            require_free_space(destination, self.profile.limits.free_space_reserve_bytes)

        return monitor

    def sync(self, sources: Sequence[str]) -> OperationResult:
        selected = [self._source(item) for item in sources]
        if not selected:
            selected = [source for source in self.database.list_sources() if source.auto_sync]
        unauthorized = [source.alias for source in selected if not source.auto_sync]
        if unauthorized:
            raise PolicyError(
                "Synchronization is allowed only for sources with automatic sync enabled",
                code="AUTO_SYNC_REQUIRED",
                sources=unauthorized,
            )
        if not selected:
            return OperationResult(
                result={
                    "plan_id": None,
                    "summary": {"total": 0, "complete": 0, "not_ready": 0, "failed": 0},
                }
            )
        with self.profile_paths.lock():
            plan = self._create_plan(
                sources=[source.alias for source in selected],
                sessions=[],
                backfill=None,
                since=None,
                last=None,
                media_policy=None,
                refresh=False,
                allow_empty=True,
            )
            result = self._apply_plan_locked(plan.plan_id)
        result.result["sync"] = True
        return result

    # Local state and diagnostics

    def status(self) -> dict[str, object]:
        try:
            auth = self.browser.status()
            authenticated = auth.authenticated
            authentication_checked_at: str | None = auth.checked_at.isoformat()
            authentication_error: str | None = None
        except AppError as error:
            authenticated = False
            authentication_checked_at = None
            authentication_error = error.code
        counts = self.database.session_counts()
        sources = self.database.list_sources()
        plans = self.database.list_plans(limit=5)
        return {
            "authenticated": authenticated,
            "authentication_checked_at": authentication_checked_at,
            "authentication_error": authentication_error,
            "source_count": len(sources),
            "auto_sync_source_count": sum(1 for source in sources if source.auto_sync),
            "sessions": {state.value: counts[state] for state in SessionState},
            "recent_plans": [
                {
                    "plan_id": plan.plan_id,
                    "created_at": plan.created_at.isoformat(),
                    "expires_at": plan.expires_at.isoformat(),
                    "item_count": len(plan.items),
                    "application": (
                        application.status.value
                        if (application := self.database.get_plan_application(plan.plan_id))
                        else None
                    ),
                }
                for plan in plans
            ],
        }

    def doctor(self) -> OperationResult:
        try:
            available = free_bytes(self.profile.output_root)
            output_ok = available >= self.profile.limits.free_space_reserve_bytes
        except OSError:
            available = 0
            output_ok = False
        checks: dict[str, object] = {
            "python": {"ok": sys.version_info >= (3, 12), "version": platform.python_version()},
            "platform": {"ok": sys.platform.startswith(("darwin", "linux")), "name": sys.platform},
            "ffmpeg": {"ok": shutil.which("ffmpeg") is not None},
            "ffprobe": {"ok": shutil.which("ffprobe") is not None},
            "browser": {
                "ok": browser_available(self.profile.browser_executable),
                "channel": self.profile.browser_channel,
            },
            "database": {"ok": self.database.schema_version() >= 1},
            "output": {
                "ok": output_ok,
                "free_bytes": available,
                "reserve_bytes": self.profile.limits.free_space_reserve_bytes,
            },
        }
        failed = [
            name
            for name, value in checks.items()
            if isinstance(value, Mapping) and not value.get("ok")
        ]
        return OperationResult(
            result={"healthy": not failed, "checks": checks},
            warnings=tuple(f"Doctor check failed: {name}" for name in failed),
            partial=bool(failed),
        )

    # Boundary helpers

    def _client(self, cookie_file: Path) -> PanoptoClient:
        return self.client_factory(
            self.profile.site_url,
            cookie_file,
            self.profile.output_root,
            quiet=True,
        )

    def _source(self, selector: str) -> Source:
        try:
            return (
                self.database.get_source(int(selector))
                if selector.isdecimal()
                else self.database.get_source_by_alias(selector)
            )
        except RecordNotFoundError as exc:
            raise UsageError("Registered source was not found", code="SOURCE_NOT_FOUND") from exc

    def _source_if_registered(self, selector: str) -> Source | None:
        if "://" in selector or _looks_like_uuid(selector):
            return None
        try:
            return self._source(selector)
        except UsageError:
            return None

    def _persist_remote_session(self, remote: PanoptoSession, source: Source | None) -> Session:
        metadata = {
            "folder_id": remote.folder_id,
            "folder_name": remote.folder_name,
            "uploader": remote.uploader,
            "description": remote.description,
            "formats": [_json_safe(item) for item in remote.formats],
            "subtitles": [_json_safe(item) for item in remote.subtitles],
            "chapters": [_json_safe(item) for item in remote.chapters],
        }
        session = Session(
            session_id=remote.session_id,
            title=remote.title,
            viewer_url=remote.url,
            recorded_at=remote.recorded_at,
            duration_seconds=remote.duration_seconds,
            state=remote.state,
            estimated_bytes=remote.estimated_bytes,
            metadata=metadata,
        )
        return self.database.upsert_session(session, source_id=source.id if source else None)

    @staticmethod
    def _public_session(stored: Session, remote: PanoptoSession | None = None) -> dict[str, object]:
        result: dict[str, object] = {
            "session_id": stored.session_id,
            "title": stored.title,
            "viewer_url": stored.viewer_url,
            "recorded_at": stored.recorded_at.isoformat() if stored.recorded_at else None,
            "duration_seconds": stored.duration_seconds,
            "state": stored.state.value,
            "estimated_bytes": stored.estimated_bytes,
        }
        if remote is not None:
            result.update(
                {
                    "folder_id": remote.folder_id,
                    "folder_name": remote.folder_name,
                    "formats": [_json_safe(item) for item in remote.formats],
                    "subtitles": [_json_safe(item) for item in remote.subtitles],
                    "chapters": [_json_safe(item) for item in remote.chapters],
                }
            )
        return result


def _public_auth(result: AuthResult) -> dict[str, object]:
    return {
        "authenticated": result.authenticated,
        "site": result.site,
        "checked_at": result.checked_at.isoformat(),
        "reason": result.reason,
    }


def _public_source(source: Source) -> dict[str, object]:
    return {
        "id": source.id,
        "folder_id": source.folder_id,
        "alias": source.alias,
        "auto_sync": source.auto_sync,
        "not_before": source.not_before.isoformat(),
        "created_at": source.created_at.isoformat(),
        "updated_at": source.updated_at.isoformat(),
        "removed_at": source.removed_at.isoformat() if source.removed_at else None,
    }


def _json_safe(value: object) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return _json_safe(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _folder_identifier(value: str, site_url: str) -> str:
    try:
        return canonical_uuid(value)
    except PolicyError:
        pass
    url = validate_allowed_url(value, site_url)
    parsed = urlsplit(url)
    if not parsed.path.lower().endswith("/panopto/pages/sessions/list.aspx"):
        raise UsageError("Expected a stable Panopto folder URL")
    values: list[str] = []
    for raw_parameters in (parsed.fragment, parsed.query):
        for key, items in parse_qs(raw_parameters, keep_blank_values=False).items():
            if key.casefold() == "folderid":
                values.extend(items)
    if len(values) != 1:
        raise UsageError("The Panopto folder URL must contain one folder ID")
    return canonical_uuid(values[0].strip('"'))


def _profile_datetime(value: datetime, profile: ProfileConfig) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=ZoneInfo(profile.timezone))
    return value.astimezone(UTC)


def _validate_history_options(
    backfill: str | None, since: datetime | None, last: int | None
) -> None:
    if backfill not in {None, "all"}:
        raise UsageError("Backfill must be 'all'")
    if sum(item is not None for item in (backfill, since, last)) > 1:
        raise UsageError("Choose only one historical selection option")
    if last is not None and last < 1:
        raise UsageError("The historical count must be positive")


def _selected_by_history(
    session: Session,
    source: Source,
    backfill: str | None,
    since: datetime | None,
    last: int | None,
) -> bool:
    if backfill == "all" or last is not None:
        return True
    timestamp = session.recorded_at
    if timestamp is None:
        return False
    if since is not None:
        return timestamp >= since
    return timestamp >= source.not_before


def _policy_estimate(session: PanoptoSession, policy: MediaPolicy) -> int | None:
    formats = list(session.formats)
    if not formats:
        return session.estimated_bytes
    if policy is MediaPolicy.ALL_STREAMS:
        sizes = [item.size_bytes for item in formats]
        return None if any(size is None for size in sizes) else sum(size for size in sizes if size)

    if policy is MediaPolicy.AUDIO:
        audio_options = [item for item in formats if _codec_present(item.audio_codec)]
        selected = _best_format(audio_options)
        return selected.size_bytes if selected is not None else None

    compatible = [item for item in formats if item.height is None or item.height <= 1080]
    podcast = [
        item
        for item in compatible
        if _codec_present(item.video_codec)
        and _codec_present(item.audio_codec)
        and item.note is not None
        and "podcast" in item.note.casefold()
    ]
    combined = [
        item
        for item in compatible
        if _codec_present(item.video_codec) and _codec_present(item.audio_codec)
    ]
    selected = _best_format(podcast) or _best_format(combined)
    if selected is not None:
        return selected.size_bytes

    video = _best_format([item for item in compatible if _codec_present(item.video_codec)])
    audio_only = _best_format(
        [
            item
            for item in compatible
            if _codec_present(item.audio_codec) and not _codec_present(item.video_codec)
        ]
    )
    if (
        video is None
        or audio_only is None
        or video.size_bytes is None
        or audio_only.size_bytes is None
    ):
        return None
    return video.size_bytes + audio_only.size_bytes


def _best_format(formats: Sequence[FormatSummary]) -> FormatSummary | None:
    if not formats:
        return None
    return max(
        formats,
        key=lambda item: (
            item.height or 0,
            item.width or 0,
            item.bitrate_kbps or 0,
            item.size_bytes or 0,
        ),
    )


def _codec_present(value: str | None) -> bool:
    return value not in {None, "none"}


def _artifact_kind(path: Path) -> ArtifactKind:
    lowered = path.name.casefold()
    if lowered == "metadata.json":
        return ArtifactKind.METADATA
    if lowered == "slides.mhtml" or path.suffix.casefold() == ".mhtml":
        return ArtifactKind.SLIDES
    if lowered.startswith("captions."):
        return ArtifactKind.CAPTION
    if path.suffix.casefold() in _MEDIA_SUFFIXES:
        return ArtifactKind.MEDIA
    return ArtifactKind.OTHER


def _is_revision_path(path: Path) -> bool:
    return _revision_number(path) is not None


def _revision_number(path: Path) -> int | None:
    raw = path.name.removeprefix("revision-")
    if path.name == raw or not raw.isdigit():
        return None
    revision = int(raw)
    return revision if revision >= 2 else None


def _item_by_id(items: Sequence[PlanItem], session_id: str) -> PlanItem:
    for item in items:
        if item.session_id == session_id:
            return item
    raise AssertionError("plan outcome referenced an unknown item")


def _stable_selector(value: str) -> str:
    if "://" not in value:
        return value
    parsed = urlsplit(value)
    return parsed.path.rsplit("/", 1)[-1] or "folder"


def _looks_like_uuid(value: str) -> bool:
    try:
        canonical_uuid(value)
    except PolicyError:
        return False
    return True
