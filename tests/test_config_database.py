from __future__ import annotations

import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from panopto_dl.config import (
    AppPaths,
    ConfigError,
    ConfigManager,
    ProfileConfig,
    validate_profile_name,
)
from panopto_dl.database import (
    DATABASE_SCHEMA_VERSION,
    ArtifactWrite,
    Database,
    DatabaseConflictError,
    InvalidSessionTransitionError,
    PlanAlreadyAppliedError,
    PlanExpiredError,
)
from panopto_dl.domain import (
    ArtifactKind,
    AttemptOutcome,
    MediaPolicy,
    PlanApplicationStatus,
    PlanItem,
    Session,
    SessionState,
)
from panopto_dl.errors import BusyError

SESSION_UUIDS = {
    "session-1": "20000000-0000-0000-0000-000000000001",
    "session-2": "20000000-0000-0000-0000-000000000002",
}


def app_paths(tmp_path: Path) -> AppPaths:
    return AppPaths(
        config_dir=tmp_path / "config",
        data_dir=tmp_path / "data",
        cache_dir=tmp_path / "cache",
    )


def session(session_id: str = "session-1") -> Session:
    return Session(
        session_id=session_id,
        title="Lecture 1",
        viewer_url=(
            "https://mediaweb.ap.panopto.com/Panopto/Pages/Viewer.aspx?"
            f"id={SESSION_UUIDS[session_id]}"
        ),
        recorded_at=datetime(2026, 8, 9, tzinfo=UTC),
        duration_seconds=3600,
        estimated_bytes=1024,
        metadata={"owner": "Lecturer"},
    )


def test_nus_preset_is_independent_of_profile_name(tmp_path: Path) -> None:
    paths = app_paths(tmp_path)
    manager = ConfigManager(paths)
    profile = manager.init_profile(
        "university",
        preset="nus",
        output_root=tmp_path / "lectures",
    )

    loaded = manager.get_profile()
    assert loaded == profile
    assert loaded.name == "university"
    assert loaded.site_url == "https://mediaweb.ap.panopto.com"
    assert loaded.timezone == "Asia/Singapore"
    assert loaded.browser_channel == "chrome"
    assert loaded.limits.max_media_jobs == 2
    assert loaded.limits.free_space_reserve_bytes == 20 * 1024**3
    assert loaded.fingerprint() == profile.fingerprint()
    assert loaded.resolve_output_path("cs1010", "lecture.mp4").is_relative_to(loaded.output_root)
    with pytest.raises(ConfigError):
        loaded.resolve_output_path("..", "elsewhere")

    assert stat.S_IMODE(paths.config_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(paths.profile("university").browser.stat().st_mode) == 0o700


def test_first_profile_is_default_even_when_no_default_is_requested(tmp_path: Path) -> None:
    manager = ConfigManager(app_paths(tmp_path))

    manager.init_profile(
        "primary",
        site_url="https://example.panopto.com",
        output_root=tmp_path / "primary",
        make_default=False,
    )
    manager.init_profile(
        "secondary",
        site_url="https://example.panopto.com",
        output_root=tmp_path / "secondary",
        make_default=False,
    )

    assert manager.load().default_profile == "primary"
    assert manager.get_profile().name == "primary"


def test_unknown_profile_preset_reports_available_presets(tmp_path: Path) -> None:
    manager = ConfigManager(app_paths(tmp_path))

    with pytest.raises(ConfigError, match=r"unknown profile preset.*nus"):
        manager.init_profile(
            "university",
            preset="unknown",
            output_root=tmp_path / "lectures",
        )


def test_profile_paths_repair_preexisting_permissive_directories(tmp_path: Path) -> None:
    profile_paths = app_paths(tmp_path).profile("nus")
    profile_paths.browser.mkdir(parents=True)
    profile_paths.root.chmod(0o755)
    profile_paths.browser.chmod(0o755)

    profile_paths.ensure()

    assert stat.S_IMODE(profile_paths.root.stat().st_mode) == 0o700
    assert stat.S_IMODE(profile_paths.browser.stat().st_mode) == 0o700


def test_invalid_stored_config_does_not_echo_browser_paths(tmp_path: Path) -> None:
    paths = app_paths(tmp_path)
    paths.config_dir.mkdir(parents=True)
    secret_browser_path = tmp_path / "SECRET_BROWSER_PATH"
    secret_browser_path.mkdir()
    paths.config_file.write_text(
        "\n".join(
            (
                "schema_version = 1",
                'default_profile = "nus"',
                "[profiles.nus]",
                'name = "nus"',
                'site_url = "https://mediaweb.ap.panopto.com"',
                'timezone = "Asia/Singapore"',
                f'output_root = "{tmp_path / "downloads"}"',
                f'browser_executable = "{secret_browser_path}"',
            )
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError) as caught:
        ConfigManager(paths).load()

    assert "SECRET_BROWSER_PATH" not in str(caught.value)


@pytest.mark.parametrize("name", ["../nus", "nus/course", "", ".hidden", "white space"])
def test_profile_names_cannot_escape_state_root(name: str) -> None:
    with pytest.raises(ConfigError):
        validate_profile_name(name)


def test_profile_rejects_query_bearing_site_and_filesystem_root(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        ProfileConfig(
            name="nus",
            site_url="https://example.panopto.com/?token=secret",
            output_root=tmp_path,
        )
    with pytest.raises(ValidationError):
        ProfileConfig(
            name="nus",
            site_url="https://not-panopto.example",
            output_root=tmp_path,
        )
    with pytest.raises(ValidationError):
        ProfileConfig(
            name="nus",
            site_url="https://example.panopto.com",
            output_root=Path("/"),
        )


def test_profile_lock_is_nonblocking(tmp_path: Path) -> None:
    profile_paths = app_paths(tmp_path).profile("nus")
    first = profile_paths.lock()
    second = profile_paths.lock()
    with first, pytest.raises(BusyError):
        second.acquire()
    with second:
        assert second.path == profile_paths.mutation_lock


@pytest.fixture
def database(tmp_path: Path) -> Database:
    return Database.open(tmp_path / "state.sqlite3")


def test_database_migration_enables_wal_and_foreign_keys(database: Database) -> None:
    assert database.schema_version() == DATABASE_SCHEMA_VERSION
    database.initialize()
    with database.connection() as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert {
        "sources",
        "sessions",
        "plans",
        "plan_items",
        "attempts",
        "artifacts",
        "schema_migrations",
    }.issubset(tables)


def test_sources_are_soft_removed_and_sessions_are_deduplicated(
    database: Database,
) -> None:
    source = database.add_source("folder-id", "cs1010")
    discovered = database.upsert_session(session(), source_id=source.id)
    renamed = database.upsert_session(
        session().model_copy(update={"title": "Lecture 1 (edited)"}),
        source_id=source.id,
    )

    assert discovered.session_id == renamed.session_id
    assert renamed.title == "Lecture 1 (edited)"
    assert len(database.list_sessions(source_id=source.id)) == 1
    removed = database.remove_source(source.id)
    assert removed.removed_at is not None
    assert database.list_sources() == ()
    assert database.get_session(discovered.session_id).title == "Lecture 1 (edited)"


def test_remote_ready_state_releases_a_not_ready_session(database: Database) -> None:
    database.upsert_session(session().model_copy(update={"state": SessionState.NOT_READY}))

    refreshed = database.upsert_session(
        session().model_copy(update={"state": SessionState.DISCOVERED})
    )

    assert refreshed.state is SessionState.DISCOVERED


def test_session_state_machine_preserves_assigned_output(
    database: Database, tmp_path: Path
) -> None:
    database.upsert_session(session())
    database.set_session_state("session-1", SessionState.PLANNED)
    database.set_session_state("session-1", SessionState.DOWNLOADING)
    output = (tmp_path / "lecture.mp4").resolve()
    complete = database.set_session_state(
        "session-1",
        SessionState.COMPLETE,
        output_path=output,
    )
    assert complete.output_path == output
    with pytest.raises(InvalidSessionTransitionError):
        database.set_session_state("session-1", SessionState.RETRYABLE_FAILED)
    with pytest.raises(InvalidSessionTransitionError):
        database.set_session_state(
            "session-1",
            SessionState.COMPLETE,
            output_path=(tmp_path / "other.mp4").resolve(),
        )


def test_downloading_session_can_return_to_not_ready(database: Database) -> None:
    database.upsert_session(session())
    database.set_session_state("session-1", SessionState.DOWNLOADING)

    updated = database.set_session_state("session-1", SessionState.NOT_READY)

    assert updated.state is SessionState.NOT_READY


def test_plans_are_content_addressed_immutable_and_single_use(
    database: Database, tmp_path: Path
) -> None:
    source = database.add_source("folder-id", "cs1010")
    database.upsert_session(session(), source_id=source.id)
    fingerprint = "a" * 64
    plan = database.create_plan(
        "nus",
        fingerprint,
        [
            PlanItem(
                session_id="session-1",
                source_id=source.id,
                output_path=(tmp_path / "lecture.mp4").resolve(),
                estimated_bytes=1024,
            )
        ],
        created_at=datetime(2026, 8, 9, 12, tzinfo=UTC),
    )

    assert plan.plan_id == plan.content_hash
    assert plan.expires_at - plan.created_at == timedelta(minutes=30)
    assert plan.estimated_bytes == 1024
    assert database.get_plan(plan.plan_id) == plan
    with database.connection() as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "UPDATE plans SET media_policy = 'audio' WHERE plan_id = ?", (plan.plan_id,)
        )

    database.begin_plan_application(
        plan.plan_id,
        fingerprint,
        started_at=datetime(2026, 8, 9, 12, 1, tzinfo=UTC),
    )
    application = database.finish_plan_application(
        plan.plan_id,
        PlanApplicationStatus.SUCCESS,
        completed_at=datetime(2026, 8, 9, 12, 2, tzinfo=UTC),
    )
    assert application.status is PlanApplicationStatus.SUCCESS
    with pytest.raises(PlanAlreadyAppliedError):
        database.validate_plan(
            plan.plan_id,
            fingerprint,
            now=datetime(2026, 8, 9, 12, 3, tzinfo=UTC),
        )


def test_expired_plan_is_rejected(database: Database, tmp_path: Path) -> None:
    database.upsert_session(session())
    plan = database.create_plan(
        "nus",
        "b" * 64,
        [PlanItem(session_id="session-1", output_path=(tmp_path / "lecture.mp4").resolve())],
        created_at=datetime(2026, 8, 9, 10, tzinfo=UTC),
    )
    with pytest.raises(PlanExpiredError):
        database.validate_plan(
            plan.plan_id,
            "b" * 64,
            now=datetime(2026, 8, 9, 10, 30, tzinfo=UTC),
        )


def test_attempts_artifacts_and_sensitive_metadata_guard(
    database: Database, tmp_path: Path
) -> None:
    database.upsert_session(session())
    attempt = database.start_attempt("session-1")
    finished = database.finish_attempt(attempt.attempt_id, AttemptOutcome.SUCCEEDED)
    assert finished.outcome is AttemptOutcome.SUCCEEDED
    assert finished.completed_at is not None

    artifact = database.add_artifact(
        "session-1",
        ArtifactKind.MEDIA,
        (tmp_path / "lecture.mp4").resolve(),
        1024,
        sha256="c" * 64,
    )
    assert database.list_artifacts("session-1") == (artifact,)

    unsafe = session("session-2").model_copy(
        update={"metadata": {"stream_url": "https://cdn.example/video?token=secret"}}
    )
    with pytest.raises(ValueError, match="sensitive field"):
        database.upsert_session(unsafe)


def test_download_completion_is_one_database_transaction(
    database: Database, tmp_path: Path
) -> None:
    database.upsert_session(session())
    output = (tmp_path / "recording").resolve()
    database.set_session_state("session-1", SessionState.PLANNED, output_path=output)
    database.set_session_state("session-1", SessionState.DOWNLOADING, output_path=output)
    attempt = database.start_attempt("session-1")
    media = (output / "lecture.mp4").resolve()
    metadata = (output / "metadata.json").resolve()

    committed = database.commit_download(
        attempt_id=attempt.attempt_id,
        session_id="session-1",
        artifacts=(
            ArtifactWrite(ArtifactKind.MEDIA, media, 10, 1, "a" * 64),
            ArtifactWrite(ArtifactKind.METADATA, metadata, 20, 1, "b" * 64),
        ),
        target_state=SessionState.COMPLETE,
        output_path=output,
        media_policy=MediaPolicy.LECTURE,
    )

    assert len(committed) == 2
    assert database.get_session("session-1").state is SessionState.COMPLETE
    assert database.list_attempts("session-1")[-1].outcome is AttemptOutcome.SUCCEEDED

    retry = database.start_attempt("session-1")
    with pytest.raises(DatabaseConflictError):
        database.commit_download(
            attempt_id=retry.attempt_id,
            session_id="session-1",
            artifacts=(ArtifactWrite(ArtifactKind.MEDIA, media, 10, 1, "a" * 64),),
            target_state=None,
            output_path=output,
            media_policy=MediaPolicy.LECTURE,
        )
    assert database.list_attempts("session-1")[-1].outcome is AttemptOutcome.RUNNING
    assert len(database.list_artifacts("session-1")) == 2


@pytest.mark.parametrize(
    "metadata",
    [
        {"transport": {"browser": {"profile": {"path": "/secret/profile"}}}},
        {"browserProfileDir": "/secret/profile"},
        {"transport": {"browser": {"profiles": ["Default"]}}},
        {"password": "secret"},
        {"passwords": ["secret"]},
        {"Proxy-Authorization": "Basic secret"},
        {"Set-Cookie": "ASPXAUTH=secret"},
        {"authenticatedResponse": {"status": 200}},
        {"http": {"response": {"body": "private API response"}}},
        {"formats": [{"httpHeaders": {"X-Test": "secret"}}]},
        {"credentials": {"accessToken": "secret"}},
        {"format": {"streamUrl": "https://cdn.example.invalid/video"}},
        {"note": "Authorization: Bearer secret"},
        {"note": "token=secret"},
        {"link": "https://cdn.example.invalid/video?expires=1&sig=secret"},
        {
            "viewer_url": (
                "https://mediaweb.ap.panopto.com/Panopto/Pages/Viewer.aspx?"
                "id=session-2&token=secret"
            )
        },
    ],
    ids=[
        "nested-browser-profile-path",
        "camel-case-browser-path",
        "plural-browser-profiles",
        "password",
        "password-list",
        "proxy-authorization",
        "set-cookie",
        "authenticated-response",
        "nested-response-body",
        "camel-case-headers",
        "nested-access-token",
        "unsigned-stream-location",
        "authorization-text",
        "token-assignment-text",
        "signed-query-url",
        "polluted-viewer-url",
    ],
)
def test_session_metadata_rejects_persistence_secrets(
    database: Database, metadata: dict[str, object]
) -> None:
    unsafe = session("session-2").model_copy(update={"metadata": metadata})

    with pytest.raises(ValueError):
        database.upsert_session(unsafe)


def test_session_title_rejects_bearer_cookie_assignments(database: Database) -> None:
    unsafe = session().model_copy(update={"title": ".ASPXAUTH=TITLE_COOKIE_SECRET"})

    with pytest.raises(ValueError):
        database.upsert_session(unsafe)


def test_session_metadata_allows_typed_safe_values_and_stable_viewer_url(
    database: Database,
) -> None:
    viewer_url = (
        f"https://mediaweb.ap.panopto.com/Panopto/Pages/Viewer.aspx?id={SESSION_UUIDS['session-2']}"
    )
    safe = session("session-2").model_copy(
        update={
            "metadata": {
                "folder_id": "folder-1",
                "folder_name": "Course folder",
                "description": "A normal lecture description",
                "viewer_url": viewer_url,
                "formats": [
                    {
                        "format_id": "podcast-1080",
                        "extension": "mp4",
                        "width": 1920,
                        "height": 1080,
                        "has_audio": True,
                    }
                ],
                "chapters": [{"title": "Introduction", "start_seconds": 0.0, "end_seconds": 42.5}],
                "subtitles": [{"language": "en-SG", "extensions": ["srt"]}],
                "optional": None,
            }
        }
    )

    stored = database.upsert_session(safe)

    assert stored.metadata == safe.metadata


@pytest.mark.parametrize(
    "viewer_url",
    [
        "http://mediaweb.ap.panopto.com/Panopto/Pages/Viewer.aspx?id=session-2",
        "https://example.invalid/Panopto/Pages/Viewer.aspx?id=session-2",
        "https://mediaweb.ap.panopto.com/Panopto/Pages/Sessions/List.aspx?id=session-2",
        "https://mediaweb.ap.panopto.com/Panopto/Pages/Viewer.aspx",
        "https://mediaweb.ap.panopto.com/Panopto/Pages/Viewer.aspx?id=SIGNED_BEARER_SECRET",
        ("https://mediaweb.ap.panopto.com/Panopto/Pages/Viewer.aspx?id=session-2&token=secret"),
        "https://user:secret@mediaweb.ap.panopto.com/Panopto/Pages/Viewer.aspx?id=session-2",
        ("https://mediaweb.ap.panopto.com/Panopto/Pages/Viewer.aspx?id=session-2#token=secret"),
    ],
)
def test_session_rejects_nonstable_viewer_urls(database: Database, viewer_url: str) -> None:
    unsafe = session("session-2").model_copy(update={"viewer_url": viewer_url})

    with pytest.raises(ValueError, match="stable HTTPS Panopto"):
        database.upsert_session(unsafe)


@pytest.mark.parametrize(
    "safe_error",
    [
        "Cookie: ASPXAUTH=secret",
        ".ASPXAUTH=secret",
        "Authorization=Bearer secret",
        "https://cdn.example.invalid/video?Signature=secret",
    ],
)
def test_attempt_error_rejects_transport_secrets(database: Database, safe_error: str) -> None:
    database.upsert_session(session())
    attempt = database.start_attempt("session-1")

    with pytest.raises(ValueError):
        database.finish_attempt(
            attempt.attempt_id,
            AttemptOutcome.RETRYABLE_FAILED,
            safe_error=safe_error,
        )


def test_media_policy_values_are_stable() -> None:
    assert MediaPolicy.ALL_STREAMS.value == "all-streams"
