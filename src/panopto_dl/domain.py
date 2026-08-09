"""Domain vocabulary shared by the CLI, planner, and persistence layer.

The models in this module deliberately contain no Panopto transport details.  A
``Session`` is the stable, safe description of a recording; signed stream URLs
and authentication material must never be placed in these models.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

PLAN_TTL = timedelta(minutes=30)


def utc_now() -> datetime:
    """Return an aware UTC timestamp.

    Kept as a function instead of a module-level value so it is safe to use as
    a Pydantic ``default_factory``.
    """

    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(_as_utc)]


class SessionState(StrEnum):
    DISCOVERED = "discovered"
    PLANNED = "planned"
    DOWNLOADING = "downloading"
    COMPLETE = "complete"
    NOT_READY = "not_ready"
    NEEDS_COMPOSITE = "needs_composite"
    RETRYABLE_FAILED = "retryable_failed"
    PERMANENT_FAILED = "permanent_failed"


class MediaPolicy(StrEnum):
    LECTURE = "lecture"
    AUDIO = "audio"
    ALL_STREAMS = "all-streams"


class AttemptOutcome(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    RETRYABLE_FAILED = "retryable_failed"
    PERMANENT_FAILED = "permanent_failed"
    INTERRUPTED = "interrupted"


class ArtifactKind(StrEnum):
    MEDIA = "media"
    CAPTION = "caption"
    METADATA = "metadata"
    SLIDES = "slides"
    CHAPTERS = "chapters"
    THUMBNAIL = "thumbnail"
    OTHER = "other"


class PlanApplicationStatus(StrEnum):
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    ERROR = "error"
    INTERRUPTED = "interrupted"


class FrozenModel(BaseModel):
    """Strict value object base used for records crossing subsystem boundaries."""

    model_config = ConfigDict(frozen=True, extra="forbid")


def _absolute_path(value: Path) -> Path:
    path = value.expanduser()
    if not path.is_absolute():
        raise ValueError("path must be absolute")
    return path


class Source(FrozenModel):
    id: int = Field(gt=0)
    folder_id: str = Field(min_length=1, max_length=256)
    alias: str = Field(min_length=1, max_length=80)
    auto_sync: bool = False
    not_before: UtcDateTime
    created_at: UtcDateTime
    updated_at: UtcDateTime
    removed_at: UtcDateTime | None = None

    @field_validator("folder_id", "alias")
    @classmethod
    def validate_safe_text(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(character) < 32 for character in value):
            raise ValueError("value must contain printable text")
        if value in {".", ".."} or "/" in value or "\\" in value:
            raise ValueError("value must not contain path separators")
        return value


class Session(FrozenModel):
    session_id: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=1024)
    viewer_url: str = Field(min_length=1, max_length=4096)
    recorded_at: UtcDateTime | None = None
    duration_seconds: float | None = Field(default=None, ge=0)
    state: SessionState = SessionState.DISCOVERED
    output_path: Path | None = None
    media_policy: MediaPolicy = MediaPolicy.LECTURE
    estimated_bytes: int | None = Field(default=None, ge=0)
    metadata: Mapping[str, Any] = Field(default_factory=dict)
    created_at: UtcDateTime = Field(default_factory=utc_now)
    updated_at: UtcDateTime = Field(default_factory=utc_now)

    @field_validator("session_id", "title", "viewer_url")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be blank")
        return value

    @field_validator("output_path")
    @classmethod
    def validate_output_path(cls, value: Path | None) -> Path | None:
        return None if value is None else _absolute_path(value)


class PlanItem(FrozenModel):
    session_id: str = Field(min_length=1, max_length=256)
    source_id: int | None = Field(default=None, gt=0)
    output_path: Path
    estimated_bytes: int | None = Field(default=None, ge=0)

    @field_validator("output_path")
    @classmethod
    def validate_output_path(cls, value: Path) -> Path:
        return _absolute_path(value)


class DownloadPlan(FrozenModel):
    plan_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_name: str = Field(min_length=1, max_length=64)
    config_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    media_policy: MediaPolicy
    items: tuple[PlanItem, ...]
    created_at: UtcDateTime
    expires_at: UtcDateTime
    sealed_at: UtcDateTime

    @property
    def estimated_bytes(self) -> int | None:
        values = [item.estimated_bytes for item in self.items]
        return None if any(value is None for value in values) else sum(values)  # type: ignore[arg-type]

    def is_expired(self, now: datetime | None = None) -> bool:
        current = _as_utc(now) if now is not None else utc_now()
        return current >= self.expires_at


class PlanApplication(FrozenModel):
    plan_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: PlanApplicationStatus
    started_at: UtcDateTime
    completed_at: UtcDateTime | None = None


class Attempt(FrozenModel):
    attempt_id: int = Field(gt=0)
    session_id: str = Field(min_length=1, max_length=256)
    plan_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    attempt_number: int = Field(gt=0)
    outcome: AttemptOutcome
    started_at: UtcDateTime
    completed_at: UtcDateTime | None = None
    error_code: str | None = Field(default=None, max_length=128)
    safe_error: str | None = Field(default=None, max_length=2048)


class Artifact(FrozenModel):
    artifact_id: int = Field(gt=0)
    session_id: str = Field(min_length=1, max_length=256)
    revision: int = Field(default=1, gt=0)
    kind: ArtifactKind
    path: Path
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    created_at: UtcDateTime

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: Path) -> Path:
        return _absolute_path(value)


ALLOWED_SESSION_TRANSITIONS: Mapping[SessionState, frozenset[SessionState]] = {
    SessionState.DISCOVERED: frozenset(
        {
            SessionState.DISCOVERED,
            SessionState.PLANNED,
            SessionState.DOWNLOADING,
            SessionState.NOT_READY,
            SessionState.RETRYABLE_FAILED,
            SessionState.PERMANENT_FAILED,
        }
    ),
    SessionState.PLANNED: frozenset(
        {
            SessionState.PLANNED,
            SessionState.DOWNLOADING,
            SessionState.NOT_READY,
            SessionState.RETRYABLE_FAILED,
            SessionState.PERMANENT_FAILED,
        }
    ),
    SessionState.DOWNLOADING: frozenset(
        {
            SessionState.DOWNLOADING,
            SessionState.COMPLETE,
            SessionState.NEEDS_COMPOSITE,
            SessionState.NOT_READY,
            SessionState.RETRYABLE_FAILED,
            SessionState.PERMANENT_FAILED,
        }
    ),
    SessionState.NOT_READY: frozenset(
        {
            SessionState.NOT_READY,
            SessionState.DISCOVERED,
            SessionState.PLANNED,
        }
    ),
    SessionState.RETRYABLE_FAILED: frozenset(
        {
            SessionState.RETRYABLE_FAILED,
            SessionState.PLANNED,
            SessionState.DOWNLOADING,
            SessionState.PERMANENT_FAILED,
        }
    ),
    SessionState.PERMANENT_FAILED: frozenset({SessionState.PERMANENT_FAILED, SessionState.PLANNED}),
    SessionState.COMPLETE: frozenset({SessionState.COMPLETE}),
    SessionState.NEEDS_COMPOSITE: frozenset({SessionState.NEEDS_COMPOSITE}),
}


def can_transition_session(current: SessionState, target: SessionState) -> bool:
    """Return whether ``target`` is a legal v0.1 state transition."""

    return target in ALLOWED_SESSION_TRANSITIONS[current]


__all__ = [
    "ALLOWED_SESSION_TRANSITIONS",
    "PLAN_TTL",
    "Artifact",
    "ArtifactKind",
    "Attempt",
    "AttemptOutcome",
    "DownloadPlan",
    "MediaPolicy",
    "PlanApplication",
    "PlanApplicationStatus",
    "PlanItem",
    "Session",
    "SessionState",
    "Source",
    "can_transition_session",
    "utc_now",
]
