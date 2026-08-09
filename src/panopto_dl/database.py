"""SQLite persistence for profile-scoped discovery and download state."""

from __future__ import annotations

import hmac
import json
import re
import sqlite3
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self
from urllib.parse import parse_qsl, urlsplit

from pydantic import ValidationError

from panopto_dl.config import validate_profile_name
from panopto_dl.domain import (
    PLAN_TTL,
    Artifact,
    ArtifactKind,
    Attempt,
    AttemptOutcome,
    DownloadPlan,
    MediaPolicy,
    PlanApplication,
    PlanApplicationStatus,
    PlanItem,
    Session,
    SessionState,
    Source,
    can_transition_session,
    utc_now,
)
from panopto_dl.errors import PolicyError
from panopto_dl.plan_hash import plan_content_hash

DATABASE_SCHEMA_VERSION = 1
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_PANOPTO_HOST_RE = re.compile(r"(?:^|\.)(?:panopto\.com|panopto\.eu)$", re.IGNORECASE)
_PANOPTO_VIEWER_PATH_RE = re.compile(r"/Panopto/Pages/(?:Viewer|Embed)\.aspx$", re.IGNORECASE)
_CREDENTIAL_TEXT_RE = re.compile(
    r"(?i)(?:^|[\s;,])(?:authorization|proxy[-_ ]authorization|cookie|set[-_ ]cookie|"
    r"password|passwd|access[-_ ]token|refresh[-_ ]token|csrf[-_ ]token|\.?aspxauth|"
    r"fedauth|rtfa|panoptoauth|arraffinity(?:samesite)?)\s*[:=]"
)
_SIGNED_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:^|[?&\s;,])(?:signature|sig|token|policy|key-pair-id|"
    r"x-amz-(?:credential|signature|security-token))\s*="
)
_SENSITIVE_KEYS = frozenset(
    {
        "authenticated_body",
        "authenticated_response",
        "authorization",
        "body",
        "browser_dir",
        "browser_path",
        "browser_profile",
        "browser_profile_dir",
        "browser_profile_path",
        "cookie",
        "cookie_file",
        "cookie_jar",
        "cookie_path",
        "cookies",
        "headers",
        "http_headers",
        "password",
        "passwd",
        "proxy_authorization",
        "raw_body",
        "raw_response",
        "request_body",
        "request_headers",
        "response",
        "response_body",
        "response_content",
        "response_headers",
        "response_json",
        "response_payload",
        "response_text",
        "set_cookie",
        "signed_stream",
        "signed_url",
        "stream_url",
        "token",
    }
)
_SECRET_KEY_PARTS = frozenset(
    {
        "authorization",
        "cookie",
        "cookies",
        "header",
        "headers",
        "passwd",
        "password",
        "passwords",
        "signature",
        "token",
        "tokens",
    }
)
_BROWSER_LOCATION_PARTS = frozenset(
    {
        "data",
        "dir",
        "directory",
        "directories",
        "dirs",
        "path",
        "paths",
        "profile",
        "profiles",
        "root",
        "roots",
        "state",
    }
)
_RESPONSE_PAYLOAD_PARTS = frozenset(
    {
        "body",
        "bodies",
        "content",
        "contents",
        "data",
        "headers",
        "json",
        "payload",
        "payloads",
        "raw",
        "text",
    }
)
_STREAM_LOCATION_PARTS = frozenset(
    {"download", "hls", "manifest", "media", "playback", "podcast", "signed", "stream"}
)


def _normalized_key(value: str) -> str:
    """Normalize mapping keys before applying deny rules.

    The persistence boundary receives data from external libraries, so callers
    must not be able to evade a rule by switching between camelCase, hyphens,
    dots, or underscores.
    """

    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", camel_split.casefold()).strip("_")


def _key_parts(value: str) -> frozenset[str]:
    return frozenset(part for part in value.split("_") if part)


def _sensitive_persistence_key(key: str, ancestors: tuple[str, ...]) -> bool:
    normalized = _normalized_key(key)
    parts = _key_parts(normalized)
    ancestor_parts = frozenset(part for ancestor in ancestors for part in _key_parts(ancestor))

    if normalized in _SENSITIVE_KEYS or parts & _SECRET_KEY_PARTS:
        return True
    if "browser" in parts and parts & _BROWSER_LOCATION_PARTS:
        return True
    if "browser" in ancestor_parts and parts & _BROWSER_LOCATION_PARTS:
        return True
    if {"proxy", "authorization"}.issubset(parts) or {"set", "cookie"}.issubset(parts):
        return True
    if "authenticated" in parts and parts & ({"response"} | _RESPONSE_PAYLOAD_PARTS):
        return True
    if "response" in parts and parts & _RESPONSE_PAYLOAD_PARTS:
        return True
    if ({"response", "authenticated"} & ancestor_parts) and parts & _RESPONSE_PAYLOAD_PARTS:
        return True
    return "url" in parts and bool(parts & _STREAM_LOCATION_PARTS)


class DatabaseError(RuntimeError):
    """A local persistence operation failed."""


class RecordNotFoundError(DatabaseError):
    pass


class DatabaseConflictError(DatabaseError):
    pass


class InvalidSessionTransitionError(DatabaseError):
    pass


class PlanNotFoundError(PolicyError):
    def __init__(self) -> None:
        super().__init__("The requested plan does not exist", code="INVALID_PLAN")


class PlanExpiredError(PolicyError):
    def __init__(self) -> None:
        super().__init__("The approved plan has expired", code="PLAN_EXPIRED")


class PlanConfigMismatchError(PolicyError):
    def __init__(self) -> None:
        super().__init__(
            "Profile configuration changed after the plan was created",
            code="PLAN_CONFIG_CHANGED",
        )


class PlanAlreadyAppliedError(PolicyError):
    def __init__(self) -> None:
        super().__init__("The approved plan has already been applied", code="PLAN_APPLIED")


@dataclass(frozen=True, slots=True)
class ArtifactWrite:
    kind: ArtifactKind
    path: Path
    size_bytes: int
    revision: int
    sha256: str


def _enum_sql(enum_type: type[Any]) -> str:
    return ", ".join(f"'{member.value}'" for member in enum_type)


_MIGRATIONS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (
        1,
        (
            """
            CREATE TABLE sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_id TEXT NOT NULL UNIQUE,
                alias TEXT NOT NULL UNIQUE COLLATE NOCASE,
                auto_sync INTEGER NOT NULL DEFAULT 0 CHECK (auto_sync IN (0, 1)),
                not_before TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                removed_at TEXT
            )
            """,
            f"""
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                viewer_url TEXT NOT NULL,
                recorded_at TEXT,
                duration_seconds REAL CHECK (duration_seconds IS NULL OR duration_seconds >= 0),
                state TEXT NOT NULL CHECK (state IN ({_enum_sql(SessionState)})),
                output_path TEXT,
                media_policy TEXT NOT NULL CHECK (media_policy IN ({_enum_sql(MediaPolicy)})),
                estimated_bytes INTEGER CHECK (estimated_bytes IS NULL OR estimated_bytes >= 0),
                metadata_json TEXT NOT NULL DEFAULT '{{}}' CHECK (json_valid(metadata_json)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE source_sessions (
                source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
                session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
                discovered_at TEXT NOT NULL,
                PRIMARY KEY (source_id, session_id)
            )
            """,
            f"""
            CREATE TABLE plans (
                plan_id TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL UNIQUE,
                profile_name TEXT NOT NULL,
                config_fingerprint TEXT NOT NULL,
                media_policy TEXT NOT NULL CHECK (media_policy IN ({_enum_sql(MediaPolicy)})),
                payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                sealed_at TEXT,
                CHECK (plan_id = content_hash),
                CHECK (expires_at > created_at)
            )
            """,
            """
            CREATE TABLE plan_items (
                plan_id TEXT NOT NULL REFERENCES plans(plan_id) ON DELETE RESTRICT,
                position INTEGER NOT NULL CHECK (position >= 0),
                session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
                source_id INTEGER REFERENCES sources(id) ON DELETE RESTRICT,
                output_path TEXT NOT NULL,
                estimated_bytes INTEGER CHECK (estimated_bytes IS NULL OR estimated_bytes >= 0),
                PRIMARY KEY (plan_id, position),
                UNIQUE (plan_id, session_id)
            )
            """,
            f"""
            CREATE TABLE plan_applications (
                plan_id TEXT PRIMARY KEY REFERENCES plans(plan_id) ON DELETE RESTRICT,
                status TEXT NOT NULL CHECK (status IN ({_enum_sql(PlanApplicationStatus)})),
                started_at TEXT NOT NULL,
                completed_at TEXT
            )
            """,
            f"""
            CREATE TABLE attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
                plan_id TEXT REFERENCES plans(plan_id) ON DELETE RESTRICT,
                attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
                outcome TEXT NOT NULL CHECK (outcome IN ({_enum_sql(AttemptOutcome)})),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                error_code TEXT,
                safe_error TEXT,
                UNIQUE (session_id, attempt_number)
            )
            """,
            f"""
            CREATE TABLE artifacts (
                artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
                revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
                kind TEXT NOT NULL CHECK (kind IN ({_enum_sql(ArtifactKind)})),
                path TEXT NOT NULL,
                sha256 TEXT,
                size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
                created_at TEXT NOT NULL,
                CHECK (sha256 IS NULL OR (length(sha256) = 64 AND sha256 GLOB '[0-9a-f]*')),
                UNIQUE (session_id, revision, kind, path)
            )
            """,
            "CREATE INDEX sessions_state_idx ON sessions(state)",
            "CREATE INDEX sessions_recorded_at_idx ON sessions(recorded_at)",
            "CREATE INDEX source_sessions_session_idx ON source_sessions(session_id)",
            "CREATE INDEX attempts_session_idx ON attempts(session_id, attempt_number)",
            "CREATE INDEX artifacts_session_idx ON artifacts(session_id, revision)",
            """
            CREATE TRIGGER sealed_plans_cannot_change
            BEFORE UPDATE ON plans
            WHEN OLD.sealed_at IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'sealed plans are immutable');
            END
            """,
            """
            CREATE TRIGGER plans_cannot_be_deleted
            BEFORE DELETE ON plans
            BEGIN
                SELECT RAISE(ABORT, 'plans are immutable');
            END
            """,
            """
            CREATE TRIGGER sealed_plan_items_cannot_be_inserted
            BEFORE INSERT ON plan_items
            WHEN (SELECT sealed_at FROM plans WHERE plan_id = NEW.plan_id) IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'sealed plan items are immutable');
            END
            """,
            """
            CREATE TRIGGER plan_items_cannot_change
            BEFORE UPDATE ON plan_items
            BEGIN
                SELECT RAISE(ABORT, 'plan items are immutable');
            END
            """,
            """
            CREATE TRIGGER plan_items_cannot_be_deleted
            BEFORE DELETE ON plan_items
            BEGIN
                SELECT RAISE(ABORT, 'plan items are immutable');
            END
            """,
        ),
    ),
)


def _to_db_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _from_db_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _required_db_time(value: str) -> datetime:
    parsed = _from_db_time(value)
    if parsed is None:  # Defensive: the type stays useful if SQLite adapters change.
        raise DatabaseError("stored timestamp is missing")
    return parsed


def _canonical_json(value: object) -> str:
    _assert_safe_to_persist(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _assert_safe_to_persist(
    value: object,
    *,
    key: str | None = None,
    ancestors: tuple[str, ...] = (),
) -> None:
    """Reject common credential and signed-URL shapes before they reach SQLite."""

    if key is not None and _sensitive_persistence_key(key, ancestors):
        raise ValueError(f"sensitive field {key!r} must not be persisted")
    next_ancestors = ancestors
    if key is not None:
        next_ancestors = (*ancestors, _normalized_key(key))
    if isinstance(value, Mapping):
        for child_key, child_value in value.items():
            _assert_safe_to_persist(
                child_value,
                key=str(child_key),
                ancestors=next_ancestors,
            )
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_safe_to_persist(child, ancestors=next_ancestors)
    elif isinstance(value, str):
        if _CREDENTIAL_TEXT_RE.search(value) or _SIGNED_ASSIGNMENT_RE.search(value):
            raise ValueError("credential or signed transport data must not be persisted")
        for candidate in _URL_RE.findall(value):
            parts = urlsplit(candidate.rstrip(".,);]"))
            if parts.username or parts.password or parts.fragment:
                raise ValueError("credential-bearing URLs must not be persisted")
            if parts.query and not _is_stable_panopto_viewer_url(candidate.rstrip(".,);]")):
                raise ValueError("signed or query-bearing URLs must not be persisted")


def _is_stable_panopto_viewer_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return False
    hostname = (parts.hostname or "").rstrip(".").casefold()
    if (
        parts.scheme.casefold() != "https"
        or not _PANOPTO_HOST_RE.search(hostname)
        or port not in {None, 443}
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or not _PANOPTO_VIEWER_PATH_RE.fullmatch(parts.path)
    ):
        return False
    try:
        parameters = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
        identifier = uuid.UUID(parameters[0][1]) if len(parameters) == 1 else None
    except (ValueError, AttributeError):
        return False
    return (
        identifier is not None
        and parameters[0][0].casefold() in {"id", "pid"}
        and str(identifier) == parameters[0][1].strip().casefold()
    )


def _validate_viewer_url(value: str) -> str:
    if not _is_stable_panopto_viewer_url(value):
        raise ValueError("viewer_url must be a stable HTTPS Panopto Viewer or Embed URL")
    return value


def _validate_sha256(value: str) -> str:
    if not _SHA256_RE.fullmatch(value):
        raise ValueError("expected a lowercase SHA-256 digest")
    return value


class Database:
    """A short-connection SQLite repository scoped to a single profile."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve(strict=False)

    @classmethod
    def open(cls, path: Path) -> Self:
        database = cls(path)
        database.initialize()
        return database

    def initialize(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            with self.connection() as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=NORMAL")
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS schema_migrations (
                            version INTEGER PRIMARY KEY,
                            applied_at TEXT NOT NULL
                        )
                        """
                    )
                    applied = {
                        int(row["version"])
                        for row in connection.execute("SELECT version FROM schema_migrations")
                    }
                    if applied and max(applied) > DATABASE_SCHEMA_VERSION:
                        raise DatabaseError("database schema is newer than this application")
                    for version, statements in _MIGRATIONS:
                        if version in applied:
                            continue
                        for statement in statements:
                            connection.execute(statement)
                        connection.execute(
                            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                            (version, _to_db_time(utc_now())),
                        )
                    connection.execute(f"PRAGMA user_version={DATABASE_SCHEMA_VERSION}")
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
            self.path.chmod(0o600)
        except (OSError, sqlite3.Error) as exc:
            raise DatabaseError("could not initialize profile database") from exc

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def schema_version(self) -> int:
        with self.connection() as connection:
            row = connection.execute("PRAGMA user_version").fetchone()
        return int(row[0])

    # Sources

    def add_source(
        self,
        folder_id: str,
        alias: str,
        *,
        auto_sync: bool = False,
        not_before: datetime | None = None,
    ) -> Source:
        now = utc_now()
        not_before = not_before or now
        # Constructing a temporary record centralises printable/path-separator validation.
        validated = Source(
            id=1,
            folder_id=folder_id,
            alias=alias,
            auto_sync=auto_sync,
            not_before=not_before,
            created_at=now,
            updated_at=now,
        )
        _assert_safe_to_persist(validated.folder_id, key="folder_id")
        _assert_safe_to_persist(validated.alias, key="alias")
        try:
            with self.transaction() as connection:
                existing = connection.execute(
                    "SELECT * FROM sources WHERE folder_id = ?", (validated.folder_id,)
                ).fetchone()
                if existing is not None and existing["removed_at"] is None:
                    raise DatabaseConflictError("source folder is already registered")
                if existing is None:
                    cursor = connection.execute(
                        """
                        INSERT INTO sources(
                            folder_id, alias, auto_sync, not_before, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            validated.folder_id,
                            validated.alias,
                            int(validated.auto_sync),
                            _to_db_time(validated.not_before),
                            _to_db_time(now),
                            _to_db_time(now),
                        ),
                    )
                    if cursor.lastrowid is None:
                        raise DatabaseError("SQLite did not return the inserted source id")
                    source_id = int(cursor.lastrowid)
                else:
                    source_id = int(existing["id"])
                    connection.execute(
                        """
                        UPDATE sources
                        SET alias = ?, auto_sync = ?, not_before = ?, updated_at = ?,
                            removed_at = NULL
                        WHERE id = ?
                        """,
                        (
                            validated.alias,
                            int(validated.auto_sync),
                            _to_db_time(validated.not_before),
                            _to_db_time(now),
                            source_id,
                        ),
                    )
                row = connection.execute(
                    "SELECT * FROM sources WHERE id = ?", (source_id,)
                ).fetchone()
        except sqlite3.IntegrityError as exc:
            raise DatabaseConflictError("source folder or alias is already registered") from exc
        return _source_from_row(row)

    def get_source(self, source_id: int, *, include_removed: bool = False) -> Source:
        query = "SELECT * FROM sources WHERE id = ?"
        if not include_removed:
            query += " AND removed_at IS NULL"
        with self.connection() as connection:
            row = connection.execute(query, (source_id,)).fetchone()
        if row is None:
            raise RecordNotFoundError("source does not exist")
        return _source_from_row(row)

    def get_source_by_alias(self, alias: str, *, include_removed: bool = False) -> Source:
        query = "SELECT * FROM sources WHERE alias = ?"
        if not include_removed:
            query += " AND removed_at IS NULL"
        with self.connection() as connection:
            row = connection.execute(query, (alias,)).fetchone()
        if row is None:
            raise RecordNotFoundError("source does not exist")
        return _source_from_row(row)

    def list_sources(self, *, include_removed: bool = False) -> tuple[Source, ...]:
        query = "SELECT * FROM sources"
        if not include_removed:
            query += " WHERE removed_at IS NULL"
        query += " ORDER BY alias COLLATE NOCASE, id"
        with self.connection() as connection:
            rows = connection.execute(query).fetchall()
        return tuple(_source_from_row(row) for row in rows)

    def configure_source(
        self,
        source_id: int,
        *,
        auto_sync: bool | None = None,
        not_before: datetime | None = None,
    ) -> Source:
        if auto_sync is None and not_before is None:
            return self.get_source(source_id)
        assignments = ["updated_at = ?"]
        parameters: list[object] = [_to_db_time(utc_now())]
        if auto_sync is not None:
            assignments.append("auto_sync = ?")
            parameters.append(int(auto_sync))
        if not_before is not None:
            assignments.append("not_before = ?")
            parameters.append(_to_db_time(not_before))
        parameters.append(source_id)
        with self.transaction() as connection:
            cursor = connection.execute(
                f"UPDATE sources SET {', '.join(assignments)} WHERE id = ? AND removed_at IS NULL",
                parameters,
            )
            if cursor.rowcount != 1:
                raise RecordNotFoundError("source does not exist")
            row = connection.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
        return _source_from_row(row)

    def remove_source(self, source_id: int, *, removed_at: datetime | None = None) -> Source:
        removed = removed_at or utc_now()
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE sources
                SET auto_sync = 0, removed_at = ?, updated_at = ?
                WHERE id = ? AND removed_at IS NULL
                """,
                (_to_db_time(removed), _to_db_time(removed), source_id),
            )
            if cursor.rowcount != 1:
                raise RecordNotFoundError("source does not exist")
            row = connection.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
        return _source_from_row(row)

    # Sessions

    def upsert_session(self, session: Session, *, source_id: int | None = None) -> Session:
        _assert_safe_to_persist(session.session_id, key="session_id")
        _assert_safe_to_persist(session.title, key="title")
        viewer_url = _validate_viewer_url(session.viewer_url)
        metadata_json = _canonical_json(dict(session.metadata))
        with self.transaction() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO sessions(
                        session_id, title, viewer_url, recorded_at, duration_seconds, state,
                        output_path, media_policy, estimated_bytes, metadata_json, created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(session_id) DO UPDATE SET
                        title = excluded.title,
                        viewer_url = excluded.viewer_url,
                        recorded_at = excluded.recorded_at,
                        duration_seconds = excluded.duration_seconds,
                        state = CASE
                            WHEN sessions.state = 'not_ready'
                                 AND excluded.state = 'discovered'
                            THEN excluded.state
                            ELSE sessions.state
                        END,
                        estimated_bytes = excluded.estimated_bytes,
                        metadata_json = excluded.metadata_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        session.session_id,
                        session.title,
                        viewer_url,
                        _to_db_time(session.recorded_at) if session.recorded_at else None,
                        session.duration_seconds,
                        session.state.value,
                        str(session.output_path) if session.output_path else None,
                        session.media_policy.value,
                        session.estimated_bytes,
                        metadata_json,
                        _to_db_time(session.created_at),
                        _to_db_time(utc_now()),
                    ),
                )
                if source_id is not None:
                    source = connection.execute(
                        "SELECT removed_at FROM sources WHERE id = ?", (source_id,)
                    ).fetchone()
                    if source is None or source["removed_at"] is not None:
                        raise RecordNotFoundError("source does not exist")
                    connection.execute(
                        """
                        INSERT INTO source_sessions(source_id, session_id, discovered_at)
                        VALUES (?, ?, ?)
                        ON CONFLICT(source_id, session_id) DO UPDATE
                        SET discovered_at = excluded.discovered_at
                        """,
                        (source_id, session.session_id, _to_db_time(utc_now())),
                    )
                row = connection.execute(
                    "SELECT * FROM sessions WHERE session_id = ?", (session.session_id,)
                ).fetchone()
            except sqlite3.IntegrityError as exc:
                raise DatabaseConflictError("could not persist session membership") from exc
        return _session_from_row(row)

    def get_session(self, session_id: str) -> Session:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        if row is None:
            raise RecordNotFoundError("session does not exist")
        return _session_from_row(row)

    def list_sessions(
        self,
        *,
        source_id: int | None = None,
        states: Sequence[SessionState] | None = None,
        recorded_after: datetime | None = None,
    ) -> tuple[Session, ...]:
        query = "SELECT DISTINCT s.* FROM sessions AS s"
        conditions: list[str] = []
        parameters: list[object] = []
        if source_id is not None:
            query += " JOIN source_sessions AS ss ON ss.session_id = s.session_id"
            conditions.append("ss.source_id = ?")
            parameters.append(source_id)
        if states:
            placeholders = ",".join("?" for _ in states)
            conditions.append(f"s.state IN ({placeholders})")
            parameters.extend(state.value for state in states)
        if recorded_after is not None:
            conditions.append("s.recorded_at >= ?")
            parameters.append(_to_db_time(recorded_after))
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY s.recorded_at, s.session_id"
        with self.connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return tuple(_session_from_row(row) for row in rows)

    def set_session_state(
        self,
        session_id: str,
        target: SessionState,
        *,
        output_path: Path | None = None,
        media_policy: MediaPolicy | None = None,
    ) -> Session:
        if output_path is not None:
            output_path = output_path.expanduser()
            if not output_path.is_absolute():
                raise ValueError("output_path must be absolute")
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if row is None:
                raise RecordNotFoundError("session does not exist")
            current = SessionState(row["state"])
            if not can_transition_session(current, target):
                raise InvalidSessionTransitionError(
                    f"cannot transition session from {current.value} to {target.value}"
                )
            existing_path = Path(row["output_path"]) if row["output_path"] else None
            if (
                existing_path is not None
                and output_path is not None
                and existing_path != output_path
            ):
                raise InvalidSessionTransitionError(
                    "a session output path cannot be changed once assigned"
                )
            selected_path = output_path or existing_path
            if target is SessionState.COMPLETE and selected_path is None:
                raise InvalidSessionTransitionError("a complete session must have an output path")
            connection.execute(
                """
                UPDATE sessions
                SET state = ?, output_path = ?, media_policy = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (
                    target.value,
                    str(selected_path) if selected_path else None,
                    (media_policy or MediaPolicy(row["media_policy"])).value,
                    _to_db_time(utc_now()),
                    session_id,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        return _session_from_row(updated)

    def session_counts(self) -> dict[SessionState, int]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT state, count(*) AS count FROM sessions GROUP BY state"
            ).fetchall()
        counts = {state: 0 for state in SessionState}
        counts.update({SessionState(row["state"]): int(row["count"]) for row in rows})
        return counts

    # Plans

    def create_plan(
        self,
        profile_name: str,
        config_fingerprint: str,
        items: Sequence[PlanItem],
        *,
        media_policy: MediaPolicy = MediaPolicy.LECTURE,
        created_at: datetime | None = None,
    ) -> DownloadPlan:
        validate_profile_name(profile_name)
        _validate_sha256(config_fingerprint)
        created = (created_at or utc_now()).astimezone(UTC)
        expires = created + PLAN_TTL
        item_tuple = tuple(items)
        session_ids = [item.session_id for item in item_tuple]
        if len(set(session_ids)) != len(session_ids):
            raise ValueError("a plan cannot contain a session more than once")
        content_hash = plan_content_hash(
            profile_name=profile_name,
            config_fingerprint=config_fingerprint,
            media_policy=media_policy,
            items=item_tuple,
            created_at=created,
            expires_at=expires,
        )
        plan = DownloadPlan(
            plan_id=content_hash,
            content_hash=content_hash,
            profile_name=profile_name,
            config_fingerprint=config_fingerprint,
            media_policy=media_policy,
            items=item_tuple,
            created_at=created,
            expires_at=expires,
            sealed_at=utc_now(),
        )
        return self.save_plan(plan)

    def save_plan(self, plan: DownloadPlan) -> DownloadPlan:
        """Persist and seal a planner-produced plan without changing its identity."""

        if plan.plan_id != plan.content_hash:
            raise ValueError("plan_id must equal the plan content hash")
        if plan.expires_at - plan.created_at != PLAN_TTL:
            raise ValueError("plans must expire exactly 30 minutes after creation")
        expected_hash = plan_content_hash(
            profile_name=plan.profile_name,
            config_fingerprint=plan.config_fingerprint,
            media_policy=plan.media_policy,
            items=plan.items,
            created_at=plan.created_at,
            expires_at=plan.expires_at,
        )
        if not hmac.compare_digest(plan.content_hash, expected_hash):
            raise ValueError("plan content hash does not match its immutable payload")
        payload_json = _canonical_json(plan.model_dump(mode="json"))
        try:
            with self.transaction() as connection:
                existing = self._get_plan_row(connection, plan.plan_id)
                if existing is not None:
                    item_rows = connection.execute(
                        "SELECT * FROM plan_items WHERE plan_id = ? ORDER BY position",
                        (plan.plan_id,),
                    ).fetchall()
                    stored = _plan_from_rows(existing, item_rows)
                    if stored == plan:
                        return stored
                    raise DatabaseConflictError("plan ID is already bound to different content")
                for item in plan.items:
                    session = connection.execute(
                        "SELECT 1 FROM sessions WHERE session_id = ?", (item.session_id,)
                    ).fetchone()
                    if session is None:
                        raise RecordNotFoundError("plan references an unknown session")
                    if item.source_id is not None:
                        membership = connection.execute(
                            """
                            SELECT 1 FROM source_sessions
                            WHERE source_id = ? AND session_id = ?
                            """,
                            (item.source_id, item.session_id),
                        ).fetchone()
                        if membership is None:
                            raise DatabaseConflictError(
                                "plan source does not contain the referenced session"
                            )
                connection.execute(
                    """
                    INSERT INTO plans(
                        plan_id, content_hash, profile_name, config_fingerprint, media_policy,
                        payload_json, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        plan.plan_id,
                        plan.content_hash,
                        plan.profile_name,
                        plan.config_fingerprint,
                        plan.media_policy.value,
                        payload_json,
                        _to_db_time(plan.created_at),
                        _to_db_time(plan.expires_at),
                    ),
                )
                for position, item in enumerate(plan.items):
                    connection.execute(
                        """
                        INSERT INTO plan_items(
                            plan_id, position, session_id, source_id, output_path, estimated_bytes
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            plan.plan_id,
                            position,
                            item.session_id,
                            item.source_id,
                            str(item.output_path),
                            item.estimated_bytes,
                        ),
                    )
                connection.execute(
                    "UPDATE plans SET sealed_at = ? WHERE plan_id = ?",
                    (_to_db_time(plan.sealed_at), plan.plan_id),
                )
        except sqlite3.IntegrityError as exc:
            raise DatabaseConflictError("could not persist immutable plan") from exc
        return self.get_plan(plan.plan_id)

    def get_plan(self, plan_id: str) -> DownloadPlan:
        with self.connection() as connection:
            plan = self._get_plan_row(connection, plan_id)
            if plan is None:
                raise PlanNotFoundError()
            items = connection.execute(
                "SELECT * FROM plan_items WHERE plan_id = ? ORDER BY position", (plan_id,)
            ).fetchall()
        return _plan_from_rows(plan, items)

    def list_plans(self, *, limit: int = 100) -> tuple[DownloadPlan, ...]:
        if limit < 1:
            raise ValueError("limit must be positive")
        with self.connection() as connection:
            plan_rows = connection.execute(
                "SELECT * FROM plans WHERE sealed_at IS NOT NULL ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            plans: list[DownloadPlan] = []
            for plan_row in plan_rows:
                item_rows = connection.execute(
                    "SELECT * FROM plan_items WHERE plan_id = ? ORDER BY position",
                    (plan_row["plan_id"],),
                ).fetchall()
                plans.append(_plan_from_rows(plan_row, item_rows))
        return tuple(plans)

    def validate_plan(
        self,
        plan_id: str,
        config_fingerprint: str,
        *,
        now: datetime | None = None,
    ) -> DownloadPlan:
        _validate_sha256(config_fingerprint)
        plan = self.get_plan(plan_id)
        if not hmac.compare_digest(plan.config_fingerprint, config_fingerprint):
            raise PlanConfigMismatchError()
        if plan.is_expired(now):
            raise PlanExpiredError()
        if self.get_plan_application(plan_id) is not None:
            raise PlanAlreadyAppliedError()
        return plan

    def begin_plan_application(
        self,
        plan_id: str,
        config_fingerprint: str,
        *,
        started_at: datetime | None = None,
    ) -> PlanApplication:
        started = started_at or utc_now()
        _validate_sha256(config_fingerprint)
        with self.transaction() as connection:
            plan_row = self._get_plan_row(connection, plan_id)
            if plan_row is None:
                raise PlanNotFoundError()
            if not hmac.compare_digest(plan_row["config_fingerprint"], config_fingerprint):
                raise PlanConfigMismatchError()
            expires = _from_db_time(plan_row["expires_at"])
            if expires is None or started.astimezone(UTC) >= expires:
                raise PlanExpiredError()
            existing = connection.execute(
                "SELECT 1 FROM plan_applications WHERE plan_id = ?", (plan_id,)
            ).fetchone()
            if existing is not None:
                raise PlanAlreadyAppliedError()
            connection.execute(
                """
                INSERT INTO plan_applications(plan_id, status, started_at)
                VALUES (?, ?, ?)
                """,
                (plan_id, PlanApplicationStatus.RUNNING.value, _to_db_time(started)),
            )
        application = self.get_plan_application(plan_id)
        assert application is not None
        return application

    def finish_plan_application(
        self,
        plan_id: str,
        status: PlanApplicationStatus,
        *,
        completed_at: datetime | None = None,
    ) -> PlanApplication:
        if status is PlanApplicationStatus.RUNNING:
            raise ValueError("a finished plan application needs a terminal status")
        completed = completed_at or utc_now()
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE plan_applications
                SET status = ?, completed_at = ?
                WHERE plan_id = ? AND status = ?
                """,
                (
                    status.value,
                    _to_db_time(completed),
                    plan_id,
                    PlanApplicationStatus.RUNNING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise RecordNotFoundError("running plan application does not exist")
        application = self.get_plan_application(plan_id)
        assert application is not None
        return application

    def get_plan_application(self, plan_id: str) -> PlanApplication | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM plan_applications WHERE plan_id = ?", (plan_id,)
            ).fetchone()
        return None if row is None else _application_from_row(row)

    @staticmethod
    def _get_plan_row(connection: sqlite3.Connection, plan_id: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = connection.execute(
            "SELECT * FROM plans WHERE plan_id = ? AND sealed_at IS NOT NULL", (plan_id,)
        ).fetchone()
        return row

    # Attempts and artifacts

    def start_attempt(
        self,
        session_id: str,
        *,
        plan_id: str | None = None,
        started_at: datetime | None = None,
    ) -> Attempt:
        started = started_at or utc_now()
        with self.transaction() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM sessions WHERE session_id = ?", (session_id,)
                ).fetchone()
                is None
            ):
                raise RecordNotFoundError("session does not exist")
            row = connection.execute(
                "SELECT COALESCE(MAX(attempt_number), 0) + 1 AS number "
                "FROM attempts WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            number = int(row["number"])
            cursor = connection.execute(
                """
                INSERT INTO attempts(
                    session_id, plan_id, attempt_number, outcome, started_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    plan_id,
                    number,
                    AttemptOutcome.RUNNING.value,
                    _to_db_time(started),
                ),
            )
            if cursor.lastrowid is None:
                raise DatabaseError("SQLite did not return the inserted attempt id")
            attempt_id = int(cursor.lastrowid)
            attempt_row = connection.execute(
                "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return _attempt_from_row(attempt_row)

    def finish_attempt(
        self,
        attempt_id: int,
        outcome: AttemptOutcome,
        *,
        error_code: str | None = None,
        safe_error: str | None = None,
        completed_at: datetime | None = None,
    ) -> Attempt:
        if outcome is AttemptOutcome.RUNNING:
            raise ValueError("a finished attempt needs a terminal outcome")
        if error_code is not None:
            _assert_safe_to_persist(error_code)
        if safe_error is not None:
            _assert_safe_to_persist(safe_error)
        completed = completed_at or utc_now()
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE attempts
                SET outcome = ?, completed_at = ?, error_code = ?, safe_error = ?
                WHERE attempt_id = ? AND outcome = ?
                """,
                (
                    outcome.value,
                    _to_db_time(completed),
                    error_code,
                    safe_error,
                    attempt_id,
                    AttemptOutcome.RUNNING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise RecordNotFoundError("running attempt does not exist")
            row = connection.execute(
                "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
        return _attempt_from_row(row)

    def list_attempts(self, session_id: str) -> tuple[Attempt, ...]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM attempts WHERE session_id = ? ORDER BY attempt_number",
                (session_id,),
            ).fetchall()
        return tuple(_attempt_from_row(row) for row in rows)

    def add_artifact(
        self,
        session_id: str,
        kind: ArtifactKind,
        path: Path,
        size_bytes: int,
        *,
        revision: int = 1,
        sha256: str | None = None,
        created_at: datetime | None = None,
    ) -> Artifact:
        path = path.expanduser()
        if not path.is_absolute():
            raise ValueError("artifact path must be absolute")
        if size_bytes < 0 or revision < 1:
            raise ValueError("artifact size and revision must be nonnegative")
        if sha256 is not None:
            _validate_sha256(sha256)
        created = created_at or utc_now()
        try:
            with self.transaction() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO artifacts(
                        session_id, revision, kind, path, sha256, size_bytes, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        revision,
                        kind.value,
                        str(path),
                        sha256,
                        size_bytes,
                        _to_db_time(created),
                    ),
                )
                if cursor.lastrowid is None:
                    raise DatabaseError("SQLite did not return the inserted artifact id")
                artifact_id = int(cursor.lastrowid)
                row = connection.execute(
                    "SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)
                ).fetchone()
        except sqlite3.IntegrityError as exc:
            raise DatabaseConflictError("could not persist artifact") from exc
        return _artifact_from_row(row)

    def commit_download(
        self,
        *,
        attempt_id: int,
        session_id: str,
        artifacts: Sequence[ArtifactWrite],
        target_state: SessionState | None,
        output_path: Path,
        media_policy: MediaPolicy,
        completed_at: datetime | None = None,
    ) -> tuple[Artifact, ...]:
        """Atomically record validated artifacts, attempt success, and completion."""

        if target_state not in {None, SessionState.COMPLETE, SessionState.NEEDS_COMPOSITE}:
            raise ValueError("a committed download needs a terminal media state")
        output_path = output_path.expanduser()
        if not output_path.is_absolute():
            raise ValueError("output_path must be absolute")
        writes = tuple(artifacts)
        if not writes:
            raise ValueError("a committed download needs at least one artifact")
        for write in writes:
            if not write.path.is_absolute() or write.size_bytes < 0 or write.revision < 1:
                raise ValueError("artifact paths, sizes, and revisions must be valid")
            _validate_sha256(write.sha256)

        completed = completed_at or utc_now()
        inserted_ids: list[int] = []
        try:
            with self.transaction() as connection:
                session = connection.execute(
                    "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
                ).fetchone()
                if session is None:
                    raise RecordNotFoundError("session does not exist")
                attempt = connection.execute(
                    "SELECT * FROM attempts WHERE attempt_id = ? AND session_id = ?",
                    (attempt_id, session_id),
                ).fetchone()
                if attempt is None or attempt["outcome"] != AttemptOutcome.RUNNING.value:
                    raise RecordNotFoundError("running attempt does not exist")

                for write in writes:
                    cursor = connection.execute(
                        """
                        INSERT INTO artifacts(
                            session_id, revision, kind, path, sha256, size_bytes, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            session_id,
                            write.revision,
                            write.kind.value,
                            str(write.path),
                            write.sha256,
                            write.size_bytes,
                            _to_db_time(completed),
                        ),
                    )
                    if cursor.lastrowid is None:
                        raise DatabaseError("SQLite did not return the inserted artifact id")
                    inserted_ids.append(int(cursor.lastrowid))

                if target_state is not None:
                    current = SessionState(session["state"])
                    if not can_transition_session(current, target_state):
                        raise InvalidSessionTransitionError(
                            "cannot transition session from "
                            f"{current.value} to {target_state.value}"
                        )
                    existing_path = Path(session["output_path"]) if session["output_path"] else None
                    if existing_path is not None and existing_path != output_path:
                        raise InvalidSessionTransitionError(
                            "a session output path cannot be changed once assigned"
                        )
                    connection.execute(
                        """
                        UPDATE sessions
                        SET state = ?, output_path = ?, media_policy = ?, updated_at = ?
                        WHERE session_id = ?
                        """,
                        (
                            target_state.value,
                            str(output_path),
                            media_policy.value,
                            _to_db_time(completed),
                            session_id,
                        ),
                    )

                connection.execute(
                    """
                    UPDATE attempts
                    SET outcome = ?, completed_at = ?
                    WHERE attempt_id = ? AND outcome = ?
                    """,
                    (
                        AttemptOutcome.SUCCEEDED.value,
                        _to_db_time(completed),
                        attempt_id,
                        AttemptOutcome.RUNNING.value,
                    ),
                )
                placeholders = ",".join("?" for _ in inserted_ids)
                rows = connection.execute(
                    f"SELECT * FROM artifacts WHERE artifact_id IN ({placeholders}) "
                    "ORDER BY artifact_id",
                    inserted_ids,
                ).fetchall()
        except sqlite3.IntegrityError as exc:
            raise DatabaseConflictError("could not commit completed download") from exc
        return tuple(_artifact_from_row(row) for row in rows)

    def list_artifacts(self, session_id: str) -> tuple[Artifact, ...]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM artifacts
                WHERE session_id = ?
                ORDER BY revision, artifact_id
                """,
                (session_id,),
            ).fetchall()
        return tuple(_artifact_from_row(row) for row in rows)


def _source_from_row(row: sqlite3.Row) -> Source:
    return Source(
        id=row["id"],
        folder_id=row["folder_id"],
        alias=row["alias"],
        auto_sync=bool(row["auto_sync"]),
        not_before=_required_db_time(row["not_before"]),
        created_at=_required_db_time(row["created_at"]),
        updated_at=_required_db_time(row["updated_at"]),
        removed_at=_from_db_time(row["removed_at"]),
    )


def _session_from_row(row: sqlite3.Row) -> Session:
    try:
        metadata = json.loads(row["metadata_json"])
        return Session(
            session_id=row["session_id"],
            title=row["title"],
            viewer_url=row["viewer_url"],
            recorded_at=_from_db_time(row["recorded_at"]),
            duration_seconds=row["duration_seconds"],
            state=SessionState(row["state"]),
            output_path=Path(row["output_path"]) if row["output_path"] else None,
            media_policy=MediaPolicy(row["media_policy"]),
            estimated_bytes=row["estimated_bytes"],
            metadata=metadata,
            created_at=_required_db_time(row["created_at"]),
            updated_at=_required_db_time(row["updated_at"]),
        )
    except (json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise DatabaseError("stored session record is invalid") from exc


def _plan_from_rows(plan: sqlite3.Row, items: Sequence[sqlite3.Row]) -> DownloadPlan:
    try:
        return DownloadPlan(
            plan_id=plan["plan_id"],
            content_hash=plan["content_hash"],
            profile_name=plan["profile_name"],
            config_fingerprint=plan["config_fingerprint"],
            media_policy=MediaPolicy(plan["media_policy"]),
            items=tuple(
                PlanItem(
                    session_id=item["session_id"],
                    source_id=item["source_id"],
                    output_path=Path(item["output_path"]),
                    estimated_bytes=item["estimated_bytes"],
                )
                for item in items
            ),
            created_at=_required_db_time(plan["created_at"]),
            expires_at=_required_db_time(plan["expires_at"]),
            sealed_at=_required_db_time(plan["sealed_at"]),
        )
    except (ValidationError, ValueError) as exc:
        raise DatabaseError("stored plan record is invalid") from exc


def _application_from_row(row: sqlite3.Row) -> PlanApplication:
    return PlanApplication(
        plan_id=row["plan_id"],
        status=PlanApplicationStatus(row["status"]),
        started_at=_required_db_time(row["started_at"]),
        completed_at=_from_db_time(row["completed_at"]),
    )


def _attempt_from_row(row: sqlite3.Row) -> Attempt:
    return Attempt(
        attempt_id=row["attempt_id"],
        session_id=row["session_id"],
        plan_id=row["plan_id"],
        attempt_number=row["attempt_number"],
        outcome=AttemptOutcome(row["outcome"]),
        started_at=_required_db_time(row["started_at"]),
        completed_at=_from_db_time(row["completed_at"]),
        error_code=row["error_code"],
        safe_error=row["safe_error"],
    )


def _artifact_from_row(row: sqlite3.Row) -> Artifact:
    return Artifact(
        artifact_id=row["artifact_id"],
        session_id=row["session_id"],
        revision=row["revision"],
        kind=ArtifactKind(row["kind"]),
        path=Path(row["path"]),
        sha256=row["sha256"],
        size_bytes=row["size_bytes"],
        created_at=_required_db_time(row["created_at"]),
    )


__all__ = [
    "DATABASE_SCHEMA_VERSION",
    "Database",
    "DatabaseConflictError",
    "DatabaseError",
    "InvalidSessionTransitionError",
    "PlanAlreadyAppliedError",
    "PlanConfigMismatchError",
    "PlanExpiredError",
    "PlanNotFoundError",
    "RecordNotFoundError",
]
