"""Deterministic, immutable download planning."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .domain import PLAN_TTL, DownloadPlan, MediaPolicy, PlanItem, Session, utc_now
from .errors import PolicyError, UsageError
from .filesystem import ensure_within_root, safe_component
from .plan_hash import plan_content_hash


@dataclass(frozen=True, slots=True)
class PlanCandidate:
    session: Session
    source_id: int | None
    source_alias: str
    output_path_override: Path | None = None


def session_output_directory(
    *,
    root: Path,
    source_alias: str,
    session: Session,
    timezone_name: str,
) -> Path:
    try:
        timezone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise UsageError("The profile timezone is invalid", timezone=timezone_name) from exc

    local_date = (
        session.recorded_at.astimezone(timezone).date().isoformat()
        if session.recorded_at is not None
        else "unknown-date"
    )
    identifier = "".join(character for character in session.session_id if character.isalnum())[:12]
    identifier = identifier or hashlib.sha256(session.session_id.encode()).hexdigest()[:12]
    directory_name = f"{local_date} - {safe_component(session.title)} [{identifier}]"
    path = root.expanduser().resolve() / safe_component(source_alias) / directory_name
    return ensure_within_root(path, root)


def build_download_plan(
    *,
    profile_name: str,
    config_fingerprint: str,
    output_root: Path,
    timezone_name: str,
    media_policy: MediaPolicy,
    candidates: list[PlanCandidate],
    max_sessions: int,
    max_estimated_bytes: int,
    now: datetime | None = None,
    allow_empty: bool = False,
) -> DownloadPlan:
    if not candidates and not allow_empty:
        raise UsageError("No downloadable sessions matched the plan request", code="PLAN_EMPTY")
    if len(candidates) > max_sessions:
        raise PolicyError(
            "The plan exceeds the profile session limit",
            code="SESSION_LIMIT_EXCEEDED",
            planned_sessions=len(candidates),
            max_sessions=max_sessions,
        )

    items = tuple(
        sorted(
            (
                PlanItem(
                    session_id=candidate.session.session_id,
                    source_id=candidate.source_id,
                    output_path=(
                        ensure_within_root(candidate.output_path_override, output_root)
                        if candidate.output_path_override is not None
                        else session_output_directory(
                            root=output_root,
                            source_alias=candidate.source_alias,
                            session=candidate.session,
                            timezone_name=timezone_name,
                        )
                    ),
                    estimated_bytes=candidate.session.estimated_bytes,
                )
                for candidate in candidates
            ),
            key=lambda item: item.session_id,
        )
    )
    known_estimate = sum(item.estimated_bytes or 0 for item in items)
    if known_estimate > max_estimated_bytes:
        raise PolicyError(
            "The plan exceeds the profile byte limit",
            code="BYTE_LIMIT_EXCEEDED",
            estimated_bytes=known_estimate,
            max_estimated_bytes=max_estimated_bytes,
        )

    created_at = now or utc_now()
    expires_at = created_at + PLAN_TTL
    content_hash = plan_content_hash(
        profile_name=profile_name,
        config_fingerprint=config_fingerprint,
        media_policy=media_policy,
        items=items,
        created_at=created_at,
        expires_at=expires_at,
    )
    return DownloadPlan(
        plan_id=content_hash,
        content_hash=content_hash,
        profile_name=profile_name,
        config_fingerprint=config_fingerprint,
        media_policy=media_policy,
        items=items,
        created_at=created_at,
        expires_at=expires_at,
        sealed_at=created_at,
    )


def plan_to_public_dict(plan: DownloadPlan) -> dict[str, object]:
    return {
        "plan_id": plan.plan_id,
        "content_hash": plan.content_hash,
        "profile": plan.profile_name,
        "media_policy": plan.media_policy.value,
        "created_at": plan.created_at.isoformat(),
        "expires_at": plan.expires_at.isoformat(),
        "item_count": len(plan.items),
        "estimated_bytes": plan.estimated_bytes,
        "items": [
            {
                "session_id": item.session_id,
                "source_id": item.source_id,
                "output_path": str(item.output_path),
                "estimated_bytes": item.estimated_bytes,
            }
            for item in plan.items
        ],
    }
