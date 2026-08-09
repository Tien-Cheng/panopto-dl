from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier

import pytest

import panopto_dl.service as service_module
from panopto_dl.browser import AuthResult
from panopto_dl.config import ProfileConfig, ProfilePaths, ResourceLimits
from panopto_dl.database import Database
from panopto_dl.domain import MediaPolicy, PlanApplicationStatus, SessionState
from panopto_dl.errors import (
    AuthenticationError,
    BusyError,
    LocalIOError,
    PolicyError,
    RemoteError,
    UsageError,
)
from panopto_dl.panopto import DownloadResult, PanoptoSession, ProgressEvent
from panopto_dl.service import AppService

SITE = "https://mediaweb.ap.panopto.com"
FOLDER_ID = "10000000-0000-0000-0000-000000000001"
SECOND_FOLDER_ID = "10000000-0000-0000-0000-000000000002"
SESSION_ONE = "20000000-0000-0000-0000-000000000001"
SESSION_TWO = "20000000-0000-0000-0000-000000000002"
SESSION_THREE = "20000000-0000-0000-0000-000000000003"


def _remote(
    session_id: str,
    *,
    title: str | None = None,
    recorded_at: datetime | None = None,
    folder_id: str = FOLDER_ID,
    state: SessionState = SessionState.DISCOVERED,
) -> PanoptoSession:
    return PanoptoSession(
        session_id=session_id,
        title=title or f"Lecture {session_id[-1]}",
        url=f"{SITE}/Panopto/Pages/Viewer.aspx?id={session_id}",
        folder_id=folder_id,
        folder_name="Course",
        recorded_at=recorded_at,
        duration_seconds=1_800,
        uploader="Lecturer",
        description="Lecture recording",
        state=state,
        estimated_bytes=1_024,
        formats=(),
        subtitles=(),
        chapters=(),
    )


DownloadEffect = BaseException | Callable[[PanoptoSession, Path, MediaPolicy], DownloadResult]


@dataclass(slots=True)
class FakeBackend:
    sessions_by_folder: dict[str, list[PanoptoSession]] = field(default_factory=dict)
    sessions_by_id: dict[str, PanoptoSession] = field(default_factory=dict)
    effects: dict[str, list[DownloadEffect | None]] = field(default_factory=dict)
    discovery_calls: list[str] = field(default_factory=list)
    download_calls: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def add(self, *sessions: PanoptoSession) -> None:
        for session in sessions:
            self.sessions_by_id[session.session_id] = session
            if session.folder_id is not None:
                self.sessions_by_folder.setdefault(session.folder_id, []).append(session)

    def factory(self, *args: object, **kwargs: object) -> FakeClient:
        return FakeClient(self)


class FakeClient:
    def __init__(self, backend: FakeBackend) -> None:
        self.backend = backend

    def discover_folders(self, url: str | None) -> list[object]:
        return []

    def discover_sessions(self, selector: str) -> list[PanoptoSession]:
        self.backend.discovery_calls.append(selector)
        return list(self.backend.sessions_by_folder.get(selector, ()))

    def inspect(self, target: str) -> PanoptoSession:
        session_id = target.rsplit("=", 1)[-1]
        return self.backend.sessions_by_id[session_id]

    def download(
        self,
        session_id: str,
        destination: Path,
        *,
        media_profile: MediaPolicy,
        progress_hook: Callable[[ProgressEvent], None],
    ) -> DownloadResult:
        self.backend.download_calls[session_id] += 1
        effects = self.backend.effects.get(session_id, [])
        effect = effects.pop(0) if effects else None
        if isinstance(effect, BaseException):
            raise effect

        session = self.backend.sessions_by_id[session_id]
        if callable(effect):
            return effect(session, destination, media_profile)

        destination.mkdir(parents=True, exist_ok=True)
        media = destination / "lecture.mp4"
        media.write_bytes(f"media:{session_id}".encode())
        progress_hook(
            ProgressEvent(
                status="downloading",
                filename=str(media),
                downloaded_bytes=media.stat().st_size,
                total_bytes=media.stat().st_size,
                speed_bytes_per_second=None,
                eta_seconds=0,
                fragment_index=1,
                fragment_count=1,
            )
        )
        return DownloadResult(
            session=session,
            media_policy=media_profile,
            state=SessionState.COMPLETE,
            destination=destination,
            artifacts=(media,),
        )


@dataclass(slots=True)
class FakeBrowser:
    root: Path
    authenticated: bool = True
    cookie_exports: int = 0

    def _result(self, authenticated: bool, reason: str) -> AuthResult:
        return AuthResult(authenticated, SITE, datetime.now(UTC), reason)

    def login(self, timeout_seconds: float = 900) -> AuthResult:
        self.authenticated = True
        return self._result(True, "AUTHENTICATED")

    def status(self) -> AuthResult:
        return self._result(
            self.authenticated,
            "AUTHENTICATED" if self.authenticated else "AUTH_REQUIRED",
        )

    def logout(self) -> AuthResult:
        self.authenticated = False
        return self._result(False, "LOGGED_OUT")

    @contextmanager
    def cookies_file(self, *, headless: bool = True) -> Iterator[Path]:
        if not self.authenticated:
            raise AuthenticationError()
        self.cookie_exports += 1
        path = self.root / f"cookies-{self.cookie_exports}.txt"
        path.write_text("# Netscape HTTP Cookie File\n", encoding="utf-8")
        path.chmod(0o600)
        try:
            yield path
        finally:
            path.unlink(missing_ok=True)


@dataclass(slots=True)
class Harness:
    service: AppService
    database: Database
    backend: FakeBackend
    browser: FakeBrowser
    profile: ProfileConfig


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    output_root = tmp_path / "downloads"
    output_root.mkdir()
    profile = ProfileConfig(
        name="nus",
        site_url=SITE,
        timezone="Asia/Singapore",
        output_root=output_root,
        browser_channel="chrome",
        limits=ResourceLimits(
            max_media_jobs=1,
            max_metadata_requests=4,
            fragment_concurrency=1,
            free_space_reserve_bytes=0,
            max_sessions_per_run=20,
            max_estimated_bytes_per_run=1024**3,
        ),
    )
    paths = ProfilePaths(tmp_path / "state")
    paths.ensure()
    database = Database.open(paths.database)
    backend = FakeBackend()
    browser = FakeBrowser(tmp_path)
    service = AppService(
        profile,
        paths,
        database,
        browser,
        lambda _: None,
        client_factory=backend.factory,
        sleeper=lambda _: None,
    )
    monkeypatch.setattr(service_module, "verify_media", lambda _: {})
    return Harness(service, database, backend, browser, profile)


def _register(
    harness: Harness,
    *,
    auto_sync: bool = False,
    not_before: datetime = datetime(2025, 1, 1, tzinfo=UTC),
) -> None:
    harness.service.source_add(
        FOLDER_ID,
        alias="course",
        auto_sync=auto_sync,
        not_before=not_before,
    )


def _plan(harness: Harness, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "sources": ["course"],
        "sessions": [],
        "backfill": None,
        "since": None,
        "last": None,
        "media_policy": None,
        "refresh": False,
    }
    values.update(overrides)
    return harness.service.create_plan(**values)  # type: ignore[arg-type]


def test_source_registration_sets_policy_and_default_cutoff(harness: Harness) -> None:
    before = datetime.now(UTC)
    payload = harness.service.source_add(
        FOLDER_ID,
        alias="course",
        auto_sync=True,
        not_before=None,
    )
    after = datetime.now(UTC)

    source = harness.database.get_source_by_alias("course")
    assert source.auto_sync is True
    assert before <= source.not_before <= after
    assert payload["source"] == {
        "id": source.id,
        "folder_id": FOLDER_ID,
        "alias": "course",
        "auto_sync": True,
        "not_before": source.not_before.isoformat(),
        "created_at": source.created_at.isoformat(),
        "updated_at": source.updated_at.isoformat(),
        "removed_at": None,
    }


def test_discovery_persists_session_and_source_membership(harness: Harness) -> None:
    _register(harness)
    remote = _remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC))
    harness.backend.add(remote)

    result = harness.service.discover_sessions("course")

    source = harness.database.get_source_by_alias("course")
    stored = harness.database.get_session(SESSION_ONE)
    assert result["session_count"] == 1
    assert stored.title == remote.title
    assert stored.metadata["folder_name"] == "Course"
    assert [item.session_id for item in harness.database.list_sessions(source_id=source.id)] == [
        SESSION_ONE
    ]


def test_plan_default_cutoff_and_backfill_all(harness: Harness) -> None:
    cutoff = datetime(2025, 2, 1, tzinfo=UTC)
    _register(harness, not_before=cutoff)
    old = _remote(SESSION_ONE, recorded_at=datetime(2025, 1, 1, tzinfo=UTC))
    new = _remote(SESSION_TWO, recorded_at=datetime(2025, 3, 1, tzinfo=UTC))
    harness.backend.add(old, new)

    default_plan = _plan(harness)
    backfill_plan = _plan(harness, backfill="all")

    assert [item["session_id"] for item in default_plan["items"]] == [SESSION_TWO]
    assert {item["session_id"] for item in backfill_plan["items"]} == {
        SESSION_ONE,
        SESSION_TWO,
    }


def test_missing_recording_timestamp_requires_explicit_backfill(harness: Harness) -> None:
    _register(harness, not_before=datetime(2025, 2, 1, tzinfo=UTC))
    harness.backend.add(_remote(SESSION_ONE, recorded_at=None))

    with pytest.raises(UsageError) as caught:
        _plan(harness)

    assert caught.value.code == "PLAN_EMPTY"
    backfill_plan = _plan(harness, backfill="all")
    assert [item["session_id"] for item in backfill_plan["items"]] == [SESSION_ONE]


def test_last_is_a_historical_selector_and_ignores_registration_cutoff(harness: Harness) -> None:
    _register(harness, not_before=datetime(2025, 6, 1, tzinfo=UTC))
    older = _remote(SESSION_ONE, recorded_at=datetime(2025, 1, 1, tzinfo=UTC))
    newest = _remote(SESSION_TWO, recorded_at=datetime(2025, 2, 1, tzinfo=UTC))
    harness.backend.add(older, newest)

    plan = _plan(harness, last=1)

    assert [item["session_id"] for item in plan["items"]] == [SESSION_TWO]


def test_apply_completes_session_and_records_artifact_hash(harness: Harness) -> None:
    _register(harness)
    remote = _remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC))
    harness.backend.add(remote)
    plan = _plan(harness)

    outcome = harness.service.apply_plan(str(plan["plan_id"]))

    stored = harness.database.get_session(SESSION_ONE)
    artifacts = harness.database.list_artifacts(SESSION_ONE)
    expected = hashlib.sha256(f"media:{SESSION_ONE}".encode()).hexdigest()
    assert outcome.partial is False
    assert outcome.result["summary"] == {
        "total": 1,
        "complete": 1,
        "not_ready": 0,
        "failed": 0,
    }
    assert stored.state is SessionState.COMPLETE
    assert stored.output_path is not None
    assert len(artifacts) == 1
    assert artifacts[0].sha256 == expected
    assert artifacts[0].path == stored.output_path / "lecture.mp4"
    assert not stored.output_path.with_name(f"{stored.output_path.name}.part").exists()
    assert (
        harness.database.get_plan_application(str(plan["plan_id"])).status
        is PlanApplicationStatus.SUCCESS
    )


def test_sync_is_idempotent_when_discovery_has_no_new_sessions(harness: Harness) -> None:
    _register(harness, auto_sync=True)
    harness.backend.add(_remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC)))

    first = harness.service.sync([])
    second = harness.service.sync([])

    assert first.result["summary"]["complete"] == 1
    assert second.result["plan_id"] is not None
    assert second.result["summary"] == {
        "total": 0,
        "complete": 0,
        "not_ready": 0,
        "failed": 0,
    }
    assert (
        harness.database.get_plan_application(str(second.result["plan_id"])).status
        is PlanApplicationStatus.SUCCESS
    )
    assert harness.backend.download_calls[SESSION_ONE] == 1


def test_refresh_creates_separate_revision_without_replacing_media(harness: Harness) -> None:
    _register(harness)
    harness.backend.add(_remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC)))
    first_plan = _plan(harness)
    harness.service.apply_plan(str(first_plan["plan_id"]))
    original = harness.database.list_artifacts(SESSION_ONE)[0]

    refresh_plan = _plan(harness, refresh=True)
    harness.service.apply_plan(str(refresh_plan["plan_id"]))

    artifacts = harness.database.list_artifacts(SESSION_ONE)
    assert original.path.is_file()
    assert [artifact.revision for artifact in artifacts] == [1, 2]
    assert artifacts[1].path.parent.name == "revision-2"
    assert harness.database.get_session(SESSION_ONE).output_path == original.path.parent


def test_stale_concurrent_refresh_plan_cannot_reuse_a_revision(harness: Harness) -> None:
    _register(harness)
    harness.backend.add(_remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC)))
    initial = _plan(harness)
    harness.service.apply_plan(str(initial["plan_id"]))
    first_refresh = _plan(harness, refresh=True)
    second_refresh = _plan(harness, refresh=True)

    harness.service.apply_plan(str(first_refresh["plan_id"]))
    with pytest.raises(PolicyError) as caught:
        harness.service.apply_plan(str(second_refresh["plan_id"]))

    assert caught.value.code == "PLAN_STALE"
    artifacts = harness.database.list_artifacts(SESSION_ONE)
    assert [artifact.revision for artifact in artifacts] == [1, 2]
    assert len({artifact.path for artifact in artifacts}) == 2


def test_authentication_failure_refreshes_cookie_then_retries(harness: Harness) -> None:
    _register(harness)
    harness.backend.add(_remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC)))
    harness.backend.effects[SESSION_ONE] = [AuthenticationError(), None]
    plan = _plan(harness)
    exports_before_apply = harness.browser.cookie_exports

    outcome = harness.service.apply_plan(str(plan["plan_id"]))

    attempts = harness.database.list_attempts(SESSION_ONE)
    assert outcome.result["summary"]["complete"] == 1
    assert harness.browser.cookie_exports - exports_before_apply == 2
    assert harness.backend.download_calls[SESSION_ONE] == 2
    assert [attempt.outcome.value for attempt in attempts] == [
        "retryable_failed",
        "succeeded",
    ]


def test_not_ready_does_not_consume_ordinary_retries(harness: Harness) -> None:
    _register(harness)
    harness.backend.add(_remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC)))
    harness.backend.effects[SESSION_ONE] = [
        RemoteError("Recording is processing", code="NOT_READY", retryable=True)
    ]
    plan = _plan(harness)

    outcome = harness.service.apply_plan(str(plan["plan_id"]))

    assert outcome.result["summary"] == {
        "total": 1,
        "complete": 0,
        "not_ready": 1,
        "failed": 0,
    }
    assert harness.backend.download_calls[SESSION_ONE] == 1
    assert len(harness.database.list_attempts(SESSION_ONE)) == 1
    assert harness.database.get_session(SESSION_ONE).state is SessionState.NOT_READY


def test_later_ready_discovery_makes_a_not_ready_session_plannable(harness: Harness) -> None:
    _register(harness)
    harness.backend.add(_remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC)))
    harness.backend.effects[SESSION_ONE] = [
        RemoteError("Recording is processing", code="NOT_READY", retryable=True)
    ]
    initial = _plan(harness)
    harness.service.apply_plan(str(initial["plan_id"]))

    ready_plan = _plan(harness)
    outcome = harness.service.apply_plan(str(ready_plan["plan_id"]))

    assert outcome.result["summary"]["complete"] == 1
    assert harness.database.get_session(SESSION_ONE).state is SessionState.COMPLETE


def test_retryable_failure_uses_three_bounded_attempts(harness: Harness) -> None:
    _register(harness)
    harness.backend.add(_remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC)))
    harness.backend.effects[SESSION_ONE] = [
        RemoteError("Temporary failure", retryable=True),
        RemoteError("Temporary failure", retryable=True),
        RemoteError("Temporary failure", retryable=True),
    ]
    delays: list[float] = []
    harness.service.sleeper = delays.append
    plan = _plan(harness)

    with pytest.raises(RemoteError):
        harness.service.apply_plan(str(plan["plan_id"]))

    assert harness.backend.download_calls[SESSION_ONE] == 3
    assert delays == [1.0, 2.0]
    assert len(harness.database.list_attempts(SESSION_ONE)) == 3
    assert harness.database.get_session(SESSION_ONE).state is SessionState.RETRYABLE_FAILED


def test_mixed_batch_returns_partial_and_preserves_each_state(harness: Harness) -> None:
    _register(harness)
    harness.backend.add(
        _remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC)),
        _remote(SESSION_TWO, recorded_at=datetime(2025, 2, 2, tzinfo=UTC)),
    )
    harness.backend.effects[SESSION_TWO] = [
        RemoteError("Unavailable", code="REMOTE_GONE", retryable=False)
    ]
    plan = _plan(harness)

    outcome = harness.service.apply_plan(str(plan["plan_id"]))

    assert outcome.partial is True
    assert outcome.result["summary"] == {
        "total": 2,
        "complete": 1,
        "not_ready": 0,
        "failed": 1,
    }
    assert outcome.warnings == (f"{SESSION_TWO}: REMOTE_GONE",)
    assert harness.database.get_session(SESSION_ONE).state is SessionState.COMPLETE
    assert harness.database.get_session(SESSION_TWO).state is SessionState.PERMANENT_FAILED
    assert (
        harness.database.get_plan_application(str(plan["plan_id"])).status
        is PlanApplicationStatus.PARTIAL
    )


def test_ffprobe_failure_does_not_commit_artifact_or_completion(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    _register(harness)
    harness.backend.add(_remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC)))
    plan = _plan(harness)
    monkeypatch.setattr(
        service_module,
        "verify_media",
        lambda _: (_ for _ in ()).throw(LocalIOError("Invalid media", code="MEDIA_INVALID")),
    )

    with pytest.raises(LocalIOError, match="Invalid media"):
        harness.service.apply_plan(str(plan["plan_id"]))

    assert harness.database.list_artifacts(SESSION_ONE) == ()
    stored = harness.database.get_session(SESSION_ONE)
    assert stored.state is SessionState.RETRYABLE_FAILED
    assert stored.output_path is not None
    assert not (stored.output_path / "lecture.mp4").exists()
    assert (
        stored.output_path.with_name(f"{stored.output_path.name}.part") / "lecture.mp4"
    ).exists()
    assert (
        harness.database.get_plan_application(str(plan["plan_id"])).status
        is PlanApplicationStatus.ERROR
    )


def test_interruption_keeps_resumable_staging_and_auditable_state(harness: Harness) -> None:
    _register(harness)
    harness.backend.add(_remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC)))

    def interrupt(
        _session: PanoptoSession, destination: Path, _policy: MediaPolicy
    ) -> DownloadResult:
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "lecture.mp4.part").write_bytes(b"resumable")
        raise KeyboardInterrupt

    harness.backend.effects[SESSION_ONE] = [interrupt]
    plan = _plan(harness)

    with pytest.raises(KeyboardInterrupt):
        harness.service.apply_plan(str(plan["plan_id"]))

    stored = harness.database.get_session(SESSION_ONE)
    attempts = harness.database.list_attempts(SESSION_ONE)
    application = harness.database.get_plan_application(str(plan["plan_id"]))
    assert stored.state is SessionState.RETRYABLE_FAILED
    assert stored.output_path is not None
    staging = stored.output_path.with_name(f"{stored.output_path.name}.part")
    assert (staging / "lecture.mp4.part").is_file()
    assert attempts[-1].outcome.value == "interrupted"
    assert application is not None
    assert application.status is PlanApplicationStatus.INTERRUPTED


def test_unexpected_download_exception_closes_the_running_attempt(harness: Harness) -> None:
    _register(harness)
    harness.backend.add(_remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC)))
    harness.backend.effects[SESSION_ONE] = [ValueError("adapter bug with private details")]
    plan = _plan(harness)

    with pytest.raises(ValueError):
        harness.service.apply_plan(str(plan["plan_id"]))

    attempt = harness.database.list_attempts(SESSION_ONE)[-1]
    assert attempt.outcome.value == "retryable_failed"
    assert attempt.error_code == "INTERNAL_ERROR"
    assert attempt.safe_error == "Unexpected internal download failure"
    assert harness.database.get_session(SESSION_ONE).state is SessionState.RETRYABLE_FAILED
    assert (
        harness.database.get_plan_application(str(plan["plan_id"])).status
        is PlanApplicationStatus.ERROR
    )


def test_parallel_interruption_cancels_workers_before_commit(harness: Harness) -> None:
    harness.service.profile = harness.profile.model_copy(
        update={"limits": harness.profile.limits.model_copy(update={"max_media_jobs": 2})}
    )
    _register(harness)
    first = _remote(SESSION_ONE, recorded_at=datetime(2025, 2, 1, tzinfo=UTC))
    second = _remote(SESSION_TWO, recorded_at=datetime(2025, 2, 2, tzinfo=UTC))
    harness.backend.add(first, second)
    started = Barrier(2)

    def interrupt(
        _session: PanoptoSession, _destination: Path, _policy: MediaPolicy
    ) -> DownloadResult:
        started.wait(timeout=1)
        raise KeyboardInterrupt

    def delayed(session: PanoptoSession, destination: Path, policy: MediaPolicy) -> DownloadResult:
        started.wait(timeout=1)
        time.sleep(0.05)
        destination.mkdir(parents=True, exist_ok=True)
        media = destination / "lecture.mp4"
        media.write_bytes(b"downloaded-before-cancellation-check")
        return DownloadResult(
            session=session,
            media_policy=policy,
            state=SessionState.COMPLETE,
            destination=destination,
            artifacts=(media,),
        )

    harness.backend.effects[SESSION_ONE] = [interrupt]
    harness.backend.effects[SESSION_TWO] = [delayed]
    plan = _plan(harness)

    with pytest.raises(KeyboardInterrupt):
        harness.service.apply_plan(str(plan["plan_id"]))

    for session_id in (SESSION_ONE, SESSION_TWO):
        assert harness.database.get_session(session_id).state is SessionState.RETRYABLE_FAILED
        assert harness.database.list_artifacts(session_id) == ()
        assert harness.database.list_attempts(session_id)[-1].outcome.value == "interrupted"
    assert (
        harness.database.get_plan_application(str(plan["plan_id"])).status
        is PlanApplicationStatus.INTERRUPTED
    )


def test_competing_mutation_returns_busy_immediately(harness: Harness) -> None:
    with harness.service.profile_paths.lock(), pytest.raises(BusyError) as raised:
        harness.service.source_add(
            SECOND_FOLDER_ID,
            alias="other",
            auto_sync=False,
            not_before=datetime(2025, 1, 1, tzinfo=UTC),
        )

    assert raised.value.code == "BUSY"
