from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from panopto_dl.domain import MediaPolicy, Session
from panopto_dl.errors import PolicyError
from panopto_dl.planner import PlanCandidate, build_download_plan, session_output_directory


def session(identifier: str = "12345678-abcd-1234-abcd-1234567890ab") -> Session:
    return Session(
        session_id=identifier,
        title="Week 1: Introduction / Questions",
        viewer_url=f"https://mediaweb.ap.panopto.com/Panopto/Pages/Viewer.aspx?id={identifier}",
        recorded_at=datetime(2026, 8, 8, 23, 30, tzinfo=UTC),
        duration_seconds=3600,
        estimated_bytes=100,
    )


def test_session_path_uses_profile_timezone_and_stable_id(tmp_path: Path) -> None:
    path = session_output_directory(
        root=tmp_path,
        source_alias="CS1010",
        session=session(),
        timezone_name="Asia/Singapore",
    )
    assert path.parent.name == "CS1010"
    assert path.name == "2026-08-09 - Week 1 Introduction Questions [12345678abcd]"


def test_plan_is_deterministic_and_expires_in_30_minutes(tmp_path: Path) -> None:
    now = datetime(2026, 8, 9, tzinfo=UTC)
    kwargs = {
        "profile_name": "nus",
        "config_fingerprint": "a" * 64,
        "output_root": tmp_path,
        "timezone_name": "Asia/Singapore",
        "media_policy": MediaPolicy.LECTURE,
        "candidates": [PlanCandidate(session(), 1, "CS1010")],
        "max_sessions": 20,
        "max_estimated_bytes": 1000,
        "now": now,
    }

    first = build_download_plan(**kwargs)  # type: ignore[arg-type]
    second = build_download_plan(**kwargs)  # type: ignore[arg-type]

    assert first.plan_id == second.plan_id
    assert (first.expires_at - first.created_at).total_seconds() == 1800

    reissued = build_download_plan(
        **(kwargs | {"now": now + timedelta(minutes=31)})  # type: ignore[arg-type]
    )
    assert reissued.plan_id != first.plan_id


def test_plan_enforces_limits(tmp_path: Path) -> None:
    candidate = PlanCandidate(session(), 1, "CS1010")
    with pytest.raises(PolicyError, match="session limit"):
        build_download_plan(
            profile_name="nus",
            config_fingerprint="a" * 64,
            output_root=tmp_path,
            timezone_name="Asia/Singapore",
            media_policy=MediaPolicy.LECTURE,
            candidates=[candidate],
            max_sessions=0,
            max_estimated_bytes=1000,
        )

    with pytest.raises(PolicyError, match="byte limit"):
        build_download_plan(
            profile_name="nus",
            config_fingerprint="a" * 64,
            output_root=tmp_path,
            timezone_name="Asia/Singapore",
            media_policy=MediaPolicy.LECTURE,
            candidates=[candidate],
            max_sessions=20,
            max_estimated_bytes=99,
        )
