from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from panopto_dl import cli
from panopto_dl.domain import MediaPolicy

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "panopto-dl" / "scripts"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


agent = _load("panopto_agent", SCRIPTS / "panopto_agent.py")
cron = _load("panopto_cron", SCRIPTS / "panopto_cron.py")


def envelope(
    command: str,
    *,
    profile: str = "nus",
    status: str = "success",
    result: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "command": command,
        "status": status,
        "profile": profile,
        "request_id": "4fd79c00-79c5-4d5e-bd7e-02a905cd15ea",
        "result": result or {},
        "warnings": [],
        "error": error,
    }


def completed(payload: dict[str, Any], returncode: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        stdout=json.dumps(payload),
        stderr="",
        returncode=returncode,
    )


def test_execute_uses_fixed_argument_array_and_shell_false(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, Any] = {}

    monkeypatch.setattr(agent.shutil, "which", lambda name: "/opt/bin/panopto-dl")

    def fake_run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        observed["command"] = command
        observed.update(kwargs)
        return completed(envelope("discover folders"))

    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    execution = agent.execute("nus", agent.Operation("discover folders", ("discover", "folders")))

    assert execution.exit_code == 0
    assert observed["command"] == [
        "/opt/bin/panopto-dl",
        "--profile",
        "nus",
        "--json",
        "--quiet",
        "--schema-version",
        "1",
        "discover",
        "folders",
    ]
    assert observed["shell"] is False
    assert observed["check"] is False
    assert observed["capture_output"] is True


def test_operation_builder_exposes_plan_apply_but_not_source_mutation() -> None:
    parser = agent.build_parser()
    parsed = parser.parse_args(
        [
            "--profile",
            "nus",
            "plan",
            "--source",
            "cs1010s",
            "--since",
            "2026-08-01",
            "--media-profile",
            "lecture",
        ]
    )
    operation = agent.operation_from_args(parsed)

    assert operation.command == "plan"
    assert operation.arguments == (
        "plan",
        "--source",
        "cs1010s",
        "--since",
        "2026-08-01",
        "--media-profile",
        "lecture",
    )
    with pytest.raises(agent.AdapterError):
        parser.parse_args(["source-add", "dangerous"])


def test_helper_requires_an_explicit_cli_compatible_profile() -> None:
    parser = agent.build_parser()

    with pytest.raises(agent.AdapterError):
        parser.parse_args(["status"])
    with pytest.raises(agent.AdapterError):
        parser.parse_args(["--profile", "university.example", "status"])


def test_discover_sessions_operation_parses_through_real_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class DiscoveryService:
        def discover_sessions(self, source: str) -> dict[str, Any]:
            calls.append(source)
            return {"source": source, "sessions": []}

    monkeypatch.setattr(cli, "_service", lambda ctx, output: DiscoveryService())
    parsed = agent.build_parser().parse_args(
        [
            "--profile",
            "university",
            "discover-sessions",
            "--source",
            "cs1010s",
            "--source",
            "ma2001",
        ]
    )
    operation = agent.operation_from_args(parsed)
    invocation = [
        "--profile",
        "university",
        "--json",
        "--quiet",
        "--schema-version",
        "1",
        *operation.arguments,
    ]

    result = CliRunner().invoke(cli.app, invocation)

    assert result.exit_code == 0, result.output
    assert calls == ["cs1010s", "ma2001"]
    assert json.loads(result.stdout)["command"] == "discover sessions"


def test_one_off_plan_operation_aliases_parse_through_real_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class PlanningService:
        def create_plan(self, **kwargs: Any) -> dict[str, Any]:
            captured.update(kwargs)
            return {"plan_id": "12345678", "item_count": 1}

    monkeypatch.setattr(cli, "_service", lambda ctx, output: PlanningService())
    target = (
        "https://mediaweb.ap.panopto.com/Panopto/Pages/Viewer.aspx"
        "?id=00000000-0000-0000-0000-000000000000"
    )
    parsed = agent.build_parser().parse_args(
        ["--profile", "university", "plan", "--target", target, "--media-profile", "lecture"]
    )
    operation = agent.operation_from_args(parsed)
    invocation = [
        "--profile",
        "university",
        "--json",
        "--quiet",
        "--schema-version",
        "1",
        *operation.arguments,
    ]

    result = CliRunner().invoke(cli.app, invocation)

    assert result.exit_code == 0, result.output
    assert captured["sessions"] == [target]
    assert captured["media_policy"] is MediaPolicy.LECTURE
    assert json.loads(result.stdout)["command"] == "plan"


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        '{}\n{"second":true}',
        json.dumps([]),
        json.dumps({**envelope("status"), "schema_version": "2.0"}),
        json.dumps({**envelope("status"), "command": "sync"}),
        json.dumps({**envelope("status"), "profile": "other"}),
        json.dumps({**envelope("status"), "extra": True}),
    ],
)
def test_parser_rejects_non_exact_or_mismatched_envelopes(raw: str) -> None:
    with pytest.raises(agent.AdapterError) as raised:
        agent.parse_cli_output(raw, expected_command="status", expected_profile="nus")
    assert raised.value.code == "INVALID_CLI_RESPONSE"


@pytest.mark.parametrize(
    "payload",
    [
        envelope(
            "status",
            result={"signed_url": "https://cdn.invalid/video?Signature=HELPER_SECRET"},
        ),
        envelope("status", result={"browserProfileDirectory": "/private/browser"}),
        {**envelope("status"), "warnings": ["Cookie: session=HELPER_SECRET"]},
        {**envelope("status"), "warnings": ["Bearer HELPER_SECRET"]},
        {**envelope("status"), "warnings": ["Signature=HELPER_SECRET"]},
        {
            **envelope("status"),
            "warnings": ["{'Authorization': 'Bearer HELPER_SECRET'}"],
        },
    ],
)
def test_parser_rejects_sensitive_material_inside_a_valid_envelope(
    payload: dict[str, Any],
) -> None:
    with pytest.raises(agent.AdapterError) as raised:
        agent.parse_cli_output(
            json.dumps(payload), expected_command="status", expected_profile="nus"
        )

    assert raised.value.code == "INVALID_CLI_RESPONSE"
    assert "HELPER_SECRET" not in raised.value.message


def test_parser_accepts_a_stable_public_panopto_viewer_url() -> None:
    viewer_url = (
        "https://mediaweb.ap.panopto.com/Panopto/Pages/Viewer.aspx?"
        "id=20000000-0000-0000-0000-000000000001"
    )
    payload = envelope("inspect", result={"session": {"viewer_url": viewer_url}})

    parsed = agent.parse_cli_output(
        json.dumps(payload), expected_command="inspect", expected_profile="nus"
    )

    assert parsed["result"]["session"]["viewer_url"] == viewer_url


def test_execute_rejects_stderr_even_with_valid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda name: "/opt/bin/panopto-dl")
    response = completed(envelope("status"))
    response.stderr = "progress"
    monkeypatch.setattr(agent.subprocess, "run", lambda *args, **kwargs: response)

    with pytest.raises(agent.AdapterError) as raised:
        agent.execute("nus", agent.Operation("status", ("status",)))
    assert raised.value.code == "INVALID_CLI_RESPONSE"


def test_execute_rejects_whitespace_only_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda name: "/opt/bin/panopto-dl")
    response = completed(envelope("status"))
    response.stderr = "\n"
    monkeypatch.setattr(agent.subprocess, "run", lambda *args, **kwargs: response)

    with pytest.raises(agent.AdapterError) as raised:
        agent.execute("nus", agent.Operation("status", ("status",)))
    assert raised.value.code == "INVALID_CLI_RESPONSE"


def test_execute_rejects_conflicting_status_and_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda name: "/opt/bin/panopto-dl")
    monkeypatch.setattr(
        agent.subprocess,
        "run",
        lambda *args, **kwargs: completed(envelope("status"), returncode=5),
    )

    with pytest.raises(agent.AdapterError) as raised:
        agent.execute("nus", agent.Operation("status", ("status",)))
    assert raised.value.code == "INVALID_CLI_RESPONSE"


def test_timeout_becomes_safe_error_without_subprocess_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda name: "/opt/bin/panopto-dl")

    def timeout(*args: Any, **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(
            cmd=["panopto-dl", "https://secret.example/?token=secret"], timeout=1
        )

    monkeypatch.setattr(agent.subprocess, "run", timeout)
    execution = agent.run(["--profile", "nus", "sync"])
    serialized = json.dumps(execution.payload)

    assert execution.exit_code == 5
    assert execution.payload["error"]["code"] == "CLI_TIMEOUT"
    assert "secret.example" not in serialized
    assert "token" not in serialized


def test_main_prints_exactly_one_json_object(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = envelope("version")
    monkeypatch.setattr(
        agent,
        "run",
        lambda argv=None: agent.Execution(payload=payload, exit_code=0),
    )

    assert agent.main(["probe"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == payload
    assert captured.out.count("\n") == 1


def test_cron_is_silent_on_success(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cron,
        "run",
        lambda profile: agent.Execution(envelope("sync"), 0),
    )

    assert cron.main(["--profile", "nus"]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_cron_emits_only_whitelisted_failure_details(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = envelope(
        "sync",
        status="error",
        result={"failed_count": 2, "signed_url": "https://secret/?token=x"},
        error={
            "code": "AUTH_REQUIRED",
            "message": "cookie expired at https://secret/?token=x",
            "retryable": True,
            "details": {
                "source": "cs1010s",
                "cookie": "secret",
                "browser_path": "/home/user/profile",
            },
        },
    )
    monkeypatch.setattr(
        cron,
        "run",
        lambda profile: agent.Execution(payload=payload, exit_code=3),
    )

    assert cron.main(["--profile", "nus"]) == 3
    output = capsys.readouterr().out
    assert "[AUTH_REQUIRED]" in output
    assert "profile=nus" in output
    assert "source=cs1010s" in output
    assert "failed_count=2" in output
    assert "secret" not in output
    assert "cookie" not in output
    assert "/home/user/profile" not in output


def test_cron_configuration_writes_owner_only_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script = tmp_path / "panopto-sync.py"
    monkeypatch.setattr(cron, "__file__", str(script))

    assert cron.main(["--configure-profile", "my_nus"]) == 0
    profile_path = tmp_path / "panopto-sync.profile"
    assert profile_path.read_text(encoding="utf-8") == "my_nus\n"
    assert profile_path.stat().st_mode & 0o777 == 0o600
    assert "my_nus" in capsys.readouterr().out


def test_cron_requires_profile_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script = tmp_path / "panopto-sync.py"
    monkeypatch.setattr(cron, "__file__", str(script))

    assert cron.main([]) == 2
    output = capsys.readouterr().out
    assert "[CRON_CONFIGURATION]" in output
    assert "profile=unknown" in output
    assert "nus" not in output.lower()
    assert "--configure-profile PROFILE" in output


@pytest.mark.parametrize("unsafe_kind", ["permissive", "symlink"])
def test_cron_rejects_unsafe_profile_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    unsafe_kind: str,
) -> None:
    script = tmp_path / "panopto-sync.py"
    profile_path = tmp_path / "panopto-sync.profile"
    if unsafe_kind == "permissive":
        profile_path.write_text("university\n", encoding="utf-8")
        profile_path.chmod(0o644)
    else:
        target = tmp_path / "profile-target"
        target.write_text("university\n", encoding="utf-8")
        profile_path.symlink_to(target)
    monkeypatch.setattr(cron, "__file__", str(script))

    assert cron.main([]) == 2
    assert "[CRON_CONFIGURATION]" in capsys.readouterr().out
