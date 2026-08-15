#!/usr/bin/env python3
"""Silent-on-success Hermes no-agent cron wrapper for panopto-dl sync."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from panopto_agent import (
    AdapterError,
    Execution,
    Operation,
    SafeArgumentParser,
    execute,
)

_SAFE_PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_SAFE_SOURCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SAFE_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
_PROFILE_FILE = "panopto-sync.profile"


def _configured_profile(script_path: Path) -> str:
    profile_path = script_path.with_name(_PROFILE_FILE)
    if profile_path.is_symlink():
        raise ValueError("profile configuration must not be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(profile_path, flags)
    with os.fdopen(descriptor, encoding="utf-8") as stream:
        details = os.fstat(stream.fileno())
        if not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) & 0o077:
            raise ValueError("profile configuration permissions are unsafe")
        profile = stream.read().strip()
    if not _SAFE_PROFILE_RE.fullmatch(profile):
        raise ValueError("invalid profile configuration")
    return profile


def _write_profile(script_path: Path, profile: str) -> None:
    if not _SAFE_PROFILE_RE.fullmatch(profile):
        raise ValueError("invalid profile")
    profile_path = script_path.with_name(_PROFILE_FILE)
    if profile_path.is_symlink():
        raise ValueError("profile configuration must not be a symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(profile_path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(profile + "\n")


def _safe_count(result: Mapping[str, Any], key: str) -> int | None:
    value = result.get(key)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _safe_source(payload: Mapping[str, Any]) -> str | None:
    error = payload.get("error")
    if not isinstance(error, Mapping):
        return None
    details = error.get("details")
    if not isinstance(details, Mapping):
        return None
    source = details.get("source")
    if isinstance(source, str) and _SAFE_SOURCE_RE.fullmatch(source):
        return source
    return None


def _error_code(payload: Mapping[str, Any]) -> str:
    if payload.get("status") == "partial":
        return "PARTIAL"
    error = payload.get("error")
    if isinstance(error, Mapping):
        code = error.get("code")
        if isinstance(code, str) and _SAFE_CODE_RE.fullmatch(code):
            return code
    return "SYNC_FAILED"


def _action_for(code: str, profile: str) -> str:
    if code == "AUTH_REQUIRED":
        return (
            f"Sign in from a desktop or RDP session with panopto-dl --profile {profile} auth login."
        )
    if code in {"DISK_FULL", "LOW_DISK", "DISK_RESERVE_REACHED"}:
        return "Free space in the configured output filesystem, then retry."
    if code == "BUSY":
        return "Wait for the active Panopto operation to finish, then retry."
    if code == "PARTIAL":
        return f"Review panopto-dl --profile {profile} status before retrying."
    if code == "CLI_UNAVAILABLE":
        return "Install panopto-dl and ensure it is available on PATH."
    return f"Run panopto-dl --profile {profile} status for safe details."


def alert_for(execution: Execution, profile: str) -> str | None:
    payload = execution.payload
    if payload.get("status") == "success" and execution.exit_code == 0:
        return None

    code = _error_code(payload)
    parts = [f"Panopto sync [{code}]", f"profile={profile}"]
    source = _safe_source(payload)
    if source is not None:
        parts.append(f"source={source}")

    result = payload.get("result")
    if isinstance(result, Mapping):
        for key in ("completed_count", "failed_count", "not_ready_count"):
            count = _safe_count(result, key)
            if count is not None:
                parts.append(f"{key}={count}")
    return " ".join(parts) + ". Action: " + _action_for(code, profile)


def run(profile: str) -> Execution:
    try:
        return execute(profile, Operation("sync", ("sync",), 24 * 60 * 60))
    except AdapterError as exc:
        from panopto_agent import _error_payload  # local import keeps one envelope source

        return Execution(
            payload=_error_payload(
                "sync",
                profile,
                code=exc.code,
                message=exc.message,
                retryable=exc.retryable,
            ),
            exit_code=exc.exit_code,
        )


def main(argv: Sequence[str] | None = None) -> int:
    try:
        parser = SafeArgumentParser(description="Silent Panopto sync cron wrapper.")
        profile_options = parser.add_mutually_exclusive_group()
        profile_options.add_argument("--profile")
        profile_options.add_argument("--configure-profile")
        args = parser.parse_args(argv)
        if args.configure_profile is not None:
            _write_profile(Path(__file__), args.configure_profile)
            print(f"Configured Panopto sync profile: {args.configure_profile}")
            return 0
        profile = args.profile or _configured_profile(Path(__file__))
        if not _SAFE_PROFILE_RE.fullmatch(profile):
            raise ValueError("invalid profile")
    except (AdapterError, OSError, ValueError):
        print(
            "Panopto sync [CRON_CONFIGURATION] profile=unknown. "
            "Action: run panopto-sync.py --configure-profile PROFILE."
        )
        return 2

    execution = run(profile)
    alert = alert_for(execution, profile)
    if alert is not None:
        print(alert)
    return execution.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
