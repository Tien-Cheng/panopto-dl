from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from panopto_dl import __version__
from panopto_dl.errors import ExitCode


@dataclass(frozen=True, slots=True)
class CliResult:
    returncode: int
    payload: dict[str, Any]


def run_machine_cli(
    tmp_path: Path, *arguments: str, expected_profile: str = ""
) -> CliResult:
    """Run the real module entrypoint with no access to the user's app directories."""

    home = tmp_path / "home"
    config = tmp_path / "xdg" / "config"
    data = tmp_path / "xdg" / "data"
    cache = tmp_path / "xdg" / "cache"
    for directory in (home, config, data, cache):
        directory.mkdir(parents=True, exist_ok=True)

    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(config),
            "XDG_DATA_HOME": str(data),
            "XDG_CACHE_HOME": str(cache),
            "NO_COLOR": "1",
            "PYTHONUTF8": "1",
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "panopto_dl.cli",
            "--json",
            "--quiet",
            "--schema-version",
            "1",
            *arguments,
        ],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
        timeout=10,
    )

    assert completed.stderr == ""
    assert completed.stdout.endswith("\n")
    assert len(completed.stdout.splitlines()) == 1
    decoded = json.loads(completed.stdout)
    assert isinstance(decoded, dict)
    assert set(decoded) == {
        "schema_version",
        "command",
        "status",
        "profile",
        "request_id",
        "result",
        "warnings",
        "error",
    }
    assert decoded["schema_version"] == "1.0"
    assert decoded["profile"] == expected_profile
    uuid.UUID(decoded["request_id"])
    assert isinstance(decoded["result"], dict)
    assert isinstance(decoded["warnings"], list)
    return CliResult(completed.returncode, decoded)


def test_version_success_is_one_machine_document(tmp_path: Path) -> None:
    result = run_machine_cli(tmp_path, "--version")

    assert result.returncode == ExitCode.SUCCESS
    assert result.payload["command"] == "version"
    assert result.payload["status"] == "success"
    assert result.payload["result"] == {"version": __version__}
    assert result.payload["error"] is None


@pytest.mark.parametrize(
    ("arguments", "command"),
    [
        (("does-not-exist",), "cli"),
        (("auth", "login", "--timeout", "1"), "auth login"),
        (("apply",), "apply"),
    ],
    ids=["unknown-command", "invalid-option-value", "missing-argument"],
)
def test_click_usage_errors_are_one_machine_document(
    tmp_path: Path,
    arguments: tuple[str, ...],
    command: str,
) -> None:
    result = run_machine_cli(tmp_path, *arguments)

    assert result.returncode == ExitCode.USAGE
    assert result.payload["command"] == command
    assert result.payload["status"] == "error"
    assert result.payload["result"] == {}
    assert result.payload["error"] == {
        "code": "INVALID_INPUT",
        "message": "Invalid command arguments",
        "retryable": False,
        "details": {},
    }


def test_unsupported_schema_is_one_machine_document(tmp_path: Path) -> None:
    result = run_machine_cli(tmp_path, "--schema-version", "2", "--version")

    assert result.returncode == ExitCode.USAGE
    assert result.payload["command"] == "version"
    assert result.payload["status"] == "error"
    assert result.payload["result"] == {}
    assert result.payload["error"] == {
        "code": "INVALID_INPUT",
        "message": "Unsupported schema version",
        "retryable": False,
        "details": {"schema_version": "2"},
    }


def test_invalid_profile_timezone_is_one_machine_document(tmp_path: Path) -> None:
    result = run_machine_cli(
        tmp_path,
        "profile",
        "init",
        "broken",
        "--preset",
        "nus",
        "--output-root",
        str(tmp_path / "downloads"),
        "--timezone",
        "Mars/Olympus",
    )

    assert result.returncode == ExitCode.USAGE
    assert result.payload["command"] == "profile init"
    assert result.payload["status"] == "error"
    assert result.payload["result"] == {}
    assert result.payload["error"] == {
        "code": "CONFIG_ERROR",
        "message": "Configuration validation failed",
        "retryable": False,
        "details": {},
    }


def test_machine_download_requires_plan_and_uses_policy_exit_code(tmp_path: Path) -> None:
    result = run_machine_cli(
        tmp_path,
        "download",
        "00000000-0000-0000-0000-000000000000",
    )

    assert result.returncode == ExitCode.POLICY
    assert result.payload["command"] == "download"
    assert result.payload["status"] == "error"
    assert result.payload["result"] == {}
    assert result.payload["error"] == {
        "code": "PLAN_REQUIRED",
        "message": "Machine callers must use plan followed by apply",
        "retryable": False,
        "details": {},
    }


def test_invalid_profile_value_is_not_echoed_in_machine_output(tmp_path: Path) -> None:
    result = run_machine_cli(
        tmp_path,
        "--profile",
        "https://example.invalid/?token=profile-secret",
        "status",
    )

    assert result.returncode == ExitCode.USAGE
    assert result.payload["profile"] == ""
    assert "profile-secret" not in json.dumps(result.payload)


def test_unconfigured_command_requires_profile_setup(tmp_path: Path) -> None:
    result = run_machine_cli(tmp_path, "status")

    assert result.returncode == ExitCode.USAGE
    assert result.payload["profile"] == ""
    assert result.payload["error"] == {
        "code": "CONFIG_ERROR",
        "message": (
            "No profile is configured. Create one with 'panopto-dl profile init NAME "
            "--site-url URL --output-root PATH', or add '--preset nus' for the NUS preset."
        ),
        "retryable": False,
        "details": {},
    }


def test_explicit_missing_profile_reports_setup_guidance(tmp_path: Path) -> None:
    result = run_machine_cli(
        tmp_path,
        "--profile",
        "university",
        "status",
        expected_profile="university",
    )

    assert result.returncode == ExitCode.USAGE
    assert result.payload["error"]["code"] == "CONFIG_ERROR"
    assert "profile init university" in result.payload["error"]["message"]


def test_first_generic_profile_becomes_default_without_nus_name(tmp_path: Path) -> None:
    output_root = tmp_path / "downloads"
    created = run_machine_cli(
        tmp_path,
        "profile",
        "init",
        "university",
        "--site-url",
        "https://example.panopto.com",
        "--output-root",
        str(output_root),
        expected_profile="university",
    )
    shown = run_machine_cli(
        tmp_path,
        "profile",
        "show",
        expected_profile="university",
    )

    assert created.returncode == ExitCode.SUCCESS
    assert created.payload["result"]["name"] == "university"
    assert shown.returncode == ExitCode.SUCCESS
    assert shown.payload["result"]["name"] == "university"


def test_profile_show_respects_global_profile_selection(tmp_path: Path) -> None:
    for name in ("primary", "secondary"):
        created = run_machine_cli(
            tmp_path,
            "profile",
            "init",
            name,
            "--site-url",
            "https://example.panopto.com",
            "--output-root",
            str(tmp_path / name),
            expected_profile=name,
        )
        assert created.returncode == ExitCode.SUCCESS

    shown = run_machine_cli(
        tmp_path,
        "--profile",
        "secondary",
        "profile",
        "show",
        expected_profile="secondary",
    )

    assert shown.returncode == ExitCode.SUCCESS
    assert shown.payload["result"]["name"] == "secondary"


def test_documented_exit_code_values_are_stable() -> None:
    assert {name: int(code) for name, code in ExitCode.__members__.items()} == {
        "SUCCESS": 0,
        "USAGE": 2,
        "AUTHENTICATION": 3,
        "POLICY": 4,
        "REMOTE": 5,
        "PARTIAL": 6,
        "LOCAL_IO": 7,
        "BUSY": 8,
        "INTERNAL": 9,
        "INTERRUPTED": 130,
    }
