#!/usr/bin/env python3
"""Constrained Hermes adapter for the panopto-dl JSON CLI."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any, NoReturn, cast
from urllib.parse import parse_qs, urlsplit

SCHEMA_VERSION = "1.0"
CLI_SCHEMA_VERSION = "1"

_PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_PLAN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{7,127}\Z")
_ERROR_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_CREDENTIAL_RE = re.compile(
    r"(?i)(?:authorization|proxy[-_ ]authorization|cookie|set[-_ ]cookie|password|"
    r"access[-_ ]token|refresh[-_ ]token|csrf[-_ ]token|\.?aspxauth|fedauth|rtfa|"
    r"panoptoauth|arraffinity(?:samesite)?)\s*[:=]"
)
_SIGNED_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:^|[?&\s;,])(?:signature|sig|token|policy|key-pair-id|"
    r"x-amz-(?:credential|signature|security-token))\s*="
)
_QUOTED_HEADER_RE = re.compile(
    r"(?i)['\"](?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-panopto-[a-z0-9_-]*|x-csrf-token)['\"]\s*:"
)
_AUTH_SCHEME_RE = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_ENCODED_URL_RE = re.compile(r"https?(?:%3a%2f%2f|:\\/\\/|:\\u002f\\u002f)", re.IGNORECASE)
_SECRET_KEY_PARTS = {
    "authorization",
    "cookie",
    "cookies",
    "header",
    "headers",
    "passwd",
    "password",
    "signature",
    "token",
}
_LOCATION_PARTS = {
    "data",
    "dir",
    "directory",
    "directories",
    "path",
    "paths",
    "profile",
    "profiles",
    "root",
    "roots",
    "state",
}
_RESPONSE_PARTS = {"body", "content", "data", "headers", "json", "payload", "raw", "text"}

_ENVELOPE_KEYS = {
    "schema_version",
    "command",
    "status",
    "profile",
    "request_id",
    "result",
    "warnings",
    "error",
}
_STATUSES = {"success", "partial", "error"}
_LONG_TIMEOUT_SECONDS = 24 * 60 * 60


class AdapterError(Exception):
    """A safe, user-facing helper failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        exit_code: int = 9,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.exit_code = exit_code


class SafeArgumentParser(argparse.ArgumentParser):
    """Keep invalid user input out of stderr and protocol errors."""

    def error(self, message: str) -> NoReturn:
        raise AdapterError(
            "INVALID_HELPER_ARGUMENTS",
            "The Panopto helper arguments are invalid.",
            exit_code=2,
        )


@dataclass(frozen=True)
class Operation:
    command: str
    arguments: tuple[str, ...]
    timeout_seconds: int = 300


@dataclass(frozen=True)
class Execution:
    payload: dict[str, Any]
    exit_code: int


def _profile(value: str) -> str:
    if not _PROFILE_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("invalid profile")
    return value


def _name(value: str) -> str:
    if not _NAME_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("invalid name")
    return value


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return parsed


def _iso_date(value: str) -> str:
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD") from exc


def _target(value: str) -> str:
    if not value or len(value) > 2048 or value.startswith("-"):
        raise argparse.ArgumentTypeError("invalid target")
    if any(ord(character) < 32 or character.isspace() for character in value):
        raise argparse.ArgumentTypeError("invalid target")

    parsed = urlsplit(value)
    if parsed.scheme:
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise argparse.ArgumentTypeError("target must be a safe HTTPS URL")
        return value

    if not _NAME_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("target must be an HTTPS URL or stable ID")
    return value


def _plan_id(value: str) -> str:
    if not _PLAN_ID_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("invalid plan ID")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        description="Constrained Hermes adapter for panopto-dl.",
        allow_abbrev=False,
    )
    parser.add_argument("--profile", required=True, type=_profile)
    subparsers = parser.add_subparsers(
        dest="operation", required=True, parser_class=SafeArgumentParser
    )

    subparsers.add_parser("probe")
    subparsers.add_parser("auth-status")
    subparsers.add_parser("discover-folders")

    sessions = subparsers.add_parser("discover-sessions")
    sessions.add_argument("--source", action="append", default=[], type=_name)

    subparsers.add_parser("source-list")
    subparsers.add_parser("status")

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("target", type=_target)

    plan = subparsers.add_parser("plan")
    plan.add_argument("--source", action="append", default=[], type=_name)
    plan.add_argument("--target", type=_target)
    history = plan.add_mutually_exclusive_group()
    history.add_argument("--backfill-all", action="store_true")
    history.add_argument("--since", type=_iso_date)
    history.add_argument("--last", type=_positive_int)
    plan.add_argument(
        "--media-profile",
        choices=("lecture", "audio", "all-streams"),
        default=None,
    )

    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("plan_id", type=_plan_id)

    subparsers.add_parser("sync")
    return parser


def operation_from_args(args: argparse.Namespace) -> Operation:
    operation = args.operation
    if operation == "probe":
        return Operation("version", ("--version",), timeout_seconds=30)
    if operation == "auth-status":
        return Operation("auth status", ("auth", "status"), timeout_seconds=120)
    if operation == "discover-folders":
        return Operation("discover folders", ("discover", "folders"))
    if operation == "discover-sessions":
        arguments: list[str] = ["discover", "sessions"]
        for source in args.source:
            arguments.extend(("--source", source))
        return Operation("discover sessions", tuple(arguments))
    if operation == "source-list":
        return Operation("source list", ("source", "list"), timeout_seconds=120)
    if operation == "inspect":
        return Operation("inspect", ("inspect", "--", args.target))
    if operation == "status":
        return Operation("status", ("status",), timeout_seconds=120)
    if operation == "plan":
        if args.target and args.source:
            raise AdapterError(
                "INVALID_HELPER_ARGUMENTS",
                "Choose a one-off target or registered sources, not both.",
                exit_code=2,
            )
        arguments = ["plan"]
        for source in args.source:
            arguments.extend(("--source", source))
        if args.target:
            arguments.extend(("--target", args.target))
        if args.backfill_all:
            arguments.extend(("--backfill", "all"))
        elif args.since:
            arguments.extend(("--since", args.since))
        elif args.last:
            arguments.extend(("--last", str(args.last)))
        if args.media_profile:
            arguments.extend(("--media-profile", args.media_profile))
        return Operation("plan", tuple(arguments))
    if operation == "apply":
        return Operation("apply", ("apply", "--", args.plan_id), _LONG_TIMEOUT_SECONDS)
    if operation == "sync":
        return Operation("sync", ("sync",), _LONG_TIMEOUT_SECONDS)
    raise AdapterError(
        "INVALID_HELPER_OPERATION",
        "The requested Panopto helper operation is not available.",
        exit_code=2,
    )


def _error_payload(
    command: str,
    profile: str,
    *,
    code: str,
    message: str,
    retryable: bool,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "status": "error",
        "profile": profile,
        "request_id": str(uuid.uuid4()),
        "result": {},
        "warnings": [],
        "error": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": {},
        },
    }


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdapterError("INVALID_CLI_RESPONSE", message)


def _validate_error(error: Any, *, required: bool) -> None:
    if error is None:
        _expect(not required, "The CLI error payload is missing.")
        return
    _expect(isinstance(error, Mapping), "The CLI error payload is invalid.")
    _expect(
        set(error) == {"code", "message", "retryable", "details"},
        "The CLI error payload has an unexpected shape.",
    )
    _expect(
        isinstance(error["code"], str) and _ERROR_CODE_RE.fullmatch(error["code"]) is not None,
        "The CLI error code is invalid.",
    )
    _expect(
        isinstance(error["message"], str) and bool(error["message"]),
        "The CLI error message is invalid.",
    )
    _expect(
        isinstance(error["retryable"], bool),
        "The CLI retryable flag is invalid.",
    )
    _expect(
        isinstance(error["details"], Mapping),
        "The CLI safe error details are invalid.",
    )


def _normalized_key(value: str) -> str:
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", camel_split.casefold()).strip("_")


def _safe_public_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    hostname = (parsed.hostname or "").rstrip(".").casefold()
    if (
        parsed.scheme != "https"
        or not hostname.endswith((".panopto.com", ".panopto.eu"))
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
    ):
        return False
    if not parsed.query and not parsed.fragment and parsed.path.rstrip("/") in {"", "/Panopto"}:
        return True
    if parsed.path in {"/Panopto/Pages/Viewer.aspx", "/Panopto/Pages/Embed.aspx"}:
        try:
            query = parse_qs(parsed.query, strict_parsing=True)
        except ValueError:
            return False
        if len(query) != 1 or not ({"id", "pid"} & set(query)) or parsed.fragment:
            return False
        values = query.get("id") or query.get("pid") or []
        try:
            return len(values) == 1 and str(uuid.UUID(values[0])) == values[0].casefold()
        except ValueError:
            return False
    if parsed.path == "/Panopto/Pages/Sessions/List.aspx" and not parsed.query:
        fragment = parse_qs(parsed.fragment)
        values = fragment.get("folderID") or []
        try:
            identifier = values[0].strip('"')
            return len(values) == 1 and str(uuid.UUID(identifier)) == identifier.casefold()
        except (IndexError, ValueError):
            return False
    return False


def _assert_safe_payload(
    value: Any,
    *,
    key: str = "",
    ancestors: tuple[str, ...] = (),
) -> None:
    normalized = _normalized_key(key)
    parts = {part for part in normalized.split("_") if part}
    ancestor_parts = {part for ancestor in ancestors for part in ancestor.split("_") if part}
    if (
        parts & _SECRET_KEY_PARTS
        or (({"browser", "playwright"} & parts) and parts & _LOCATION_PARTS)
        or (({"browser", "playwright"} & ancestor_parts) and parts & _LOCATION_PARTS)
        or ("response" in parts and parts & _RESPONSE_PARTS)
        or (({"response", "authenticated"} & ancestor_parts) and parts & _RESPONSE_PARTS)
    ):
        raise AdapterError(
            "INVALID_CLI_RESPONSE",
            "The CLI response contains a forbidden sensitive field.",
        )
    next_ancestors = (*ancestors, normalized) if normalized else ancestors
    if isinstance(value, Mapping):
        for child_key, child_value in value.items():
            _assert_safe_payload(
                child_value,
                key=str(child_key),
                ancestors=next_ancestors,
            )
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_safe_payload(child, ancestors=next_ancestors)
    elif isinstance(value, str):
        if (
            _CREDENTIAL_RE.search(value)
            or _SIGNED_ASSIGNMENT_RE.search(value)
            or _QUOTED_HEADER_RE.search(value)
            or _AUTH_SCHEME_RE.search(value)
            or _ENCODED_URL_RE.search(value)
        ):
            raise AdapterError(
                "INVALID_CLI_RESPONSE",
                "The CLI response contains forbidden credential material.",
            )
        for candidate in _URL_RE.findall(value):
            if not _safe_public_url(candidate.rstrip(".,);]")):
                raise AdapterError(
                    "INVALID_CLI_RESPONSE",
                    "The CLI response contains a forbidden transport URL.",
                )


def validate_envelope(
    value: Any,
    *,
    expected_command: str,
    expected_profile: str,
) -> dict[str, Any]:
    _expect(isinstance(value, dict), "The CLI response is not a JSON object.")
    _expect(
        set(value) == _ENVELOPE_KEYS,
        "The CLI response has an unexpected top-level shape.",
    )
    _expect(
        value["schema_version"] == SCHEMA_VERSION,
        "The CLI schema version is unsupported.",
    )
    _expect(
        value["command"] == expected_command,
        "The CLI response names a different command.",
    )
    _expect(
        value["profile"] == expected_profile,
        "The CLI response names a different profile.",
    )
    _expect(value["status"] in _STATUSES, "The CLI status is invalid.")
    _expect(
        isinstance(value["request_id"], str) and bool(value["request_id"]),
        "The CLI request ID is invalid.",
    )
    _expect(isinstance(value["result"], dict), "The CLI result is invalid.")
    _expect(isinstance(value["warnings"], list), "The CLI warnings are invalid.")
    _validate_error(value["error"], required=value["status"] == "error")
    if value["status"] == "success":
        _expect(value["error"] is None, "A successful CLI response contains an error.")
    _assert_safe_payload(value)
    return cast(dict[str, Any], value)


def parse_cli_output(
    stdout: str,
    *,
    expected_command: str,
    expected_profile: str,
) -> dict[str, Any]:
    try:
        value = json.loads(stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise AdapterError(
            "INVALID_CLI_RESPONSE",
            "The CLI did not return exactly one valid JSON object.",
        ) from exc
    return validate_envelope(
        value,
        expected_command=expected_command,
        expected_profile=expected_profile,
    )


def execute(profile: str, operation: Operation) -> Execution:
    binary = shutil.which("panopto-dl")
    if binary is None:
        raise AdapterError(
            "CLI_UNAVAILABLE",
            "panopto-dl is not installed or is not available on PATH.",
            exit_code=2,
        )

    command = [
        binary,
        "--profile",
        profile,
        "--json",
        "--quiet",
        "--schema-version",
        CLI_SCHEMA_VERSION,
        *operation.arguments,
    ]
    try:
        completed = subprocess.run(
            command,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=operation.timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise AdapterError(
            "CLI_TIMEOUT",
            "The Panopto operation exceeded the helper time limit.",
            retryable=True,
            exit_code=5,
        ) from exc
    except OSError as exc:
        raise AdapterError(
            "CLI_UNAVAILABLE",
            "panopto-dl could not be started.",
            exit_code=2,
        ) from exc

    if completed.stderr:
        raise AdapterError(
            "INVALID_CLI_RESPONSE",
            "The quiet CLI wrote unexpected diagnostic output.",
        )
    payload = parse_cli_output(
        completed.stdout,
        expected_command=operation.command,
        expected_profile=profile,
    )
    status = payload["status"]
    if status == "success" and completed.returncode != 0:
        raise AdapterError(
            "INVALID_CLI_RESPONSE",
            "The CLI success status conflicts with its exit code.",
        )
    if status == "partial" and completed.returncode != 6:
        raise AdapterError(
            "INVALID_CLI_RESPONSE",
            "The CLI partial status conflicts with its exit code.",
        )
    if status == "error" and completed.returncode == 0:
        raise AdapterError(
            "INVALID_CLI_RESPONSE",
            "The CLI error status conflicts with its exit code.",
        )
    return Execution(payload=payload, exit_code=completed.returncode)


def run(argv: Sequence[str] | None = None) -> Execution:
    arguments = list(argv) if argv is not None else sys.argv[1:]
    profile = "unknown"
    try:
        parsed = build_parser().parse_args(arguments)
        profile = parsed.profile
        operation = operation_from_args(parsed)
        return execute(profile, operation)
    except AdapterError as exc:
        command = "helper"
        return Execution(
            payload=_error_payload(
                command,
                profile,
                code=exc.code,
                message=exc.message,
                retryable=exc.retryable,
            ),
            exit_code=exc.exit_code,
        )


def main(argv: Sequence[str] | None = None) -> int:
    execution = run(argv)
    print(json.dumps(execution.payload, separators=(",", ":"), sort_keys=True))
    return execution.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
