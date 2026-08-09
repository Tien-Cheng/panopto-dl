"""Canonical content identity for immutable download plans."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from .domain import MediaPolicy, PlanItem


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("plan timestamps must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def plan_content_payload(
    *,
    profile_name: str,
    config_fingerprint: str,
    media_policy: MediaPolicy,
    items: tuple[PlanItem, ...],
    created_at: datetime,
    expires_at: datetime,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "profile_name": profile_name,
        "config_fingerprint": config_fingerprint,
        "media_policy": media_policy.value,
        "created_at": _timestamp(created_at),
        "expires_at": _timestamp(expires_at),
        "items": [
            {
                "session_id": item.session_id,
                "source_id": item.source_id,
                "output_path": str(Path(item.output_path)),
                "estimated_bytes": item.estimated_bytes,
            }
            for item in items
        ],
    }


def plan_content_hash(
    *,
    profile_name: str,
    config_fingerprint: str,
    media_policy: MediaPolicy,
    items: tuple[PlanItem, ...],
    created_at: datetime,
    expires_at: datetime,
) -> str:
    payload = plan_content_payload(
        profile_name=profile_name,
        config_fingerprint=config_fingerprint,
        media_policy=media_policy,
        items=items,
        created_at=created_at,
        expires_at=expires_at,
    )
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
