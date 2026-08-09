from __future__ import annotations

import json
from pathlib import Path

import pytest

from panopto_dl.errors import AuthenticationError, ExitCode, LocalIOError, PolicyError
from panopto_dl.filesystem import (
    ensure_no_symlink_components,
    ensure_within_root,
    free_bytes,
    require_free_space,
    safe_component,
    sha256_file,
)
from panopto_dl.output import OutputContext


def test_machine_success_is_one_json_object(capsys: pytest.CaptureFixture[str]) -> None:
    output = OutputContext(
        command="status",
        profile="nus",
        json_mode=True,
        quiet=True,
        request_id="request-1",
    )

    output.emit_success({"authenticated": True})

    captured = capsys.readouterr()
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload == {
        "schema_version": "1.0",
        "command": "status",
        "status": "success",
        "profile": "nus",
        "request_id": "request-1",
        "result": {"authenticated": True},
        "warnings": [],
        "error": None,
    }
    assert captured.out.count("\n") == 1


def test_machine_error_uses_stable_contract(capsys: pytest.CaptureFixture[str]) -> None:
    output = OutputContext(
        command="auth status",
        profile="nus",
        json_mode=True,
        quiet=True,
        request_id="request-2",
    )

    exit_code = output.emit_error(AuthenticationError())

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == ExitCode.AUTHENTICATION
    assert payload["status"] == "error"
    assert payload["result"] == {}
    assert payload["error"]["code"] == "AUTH_REQUIRED"
    assert payload["error"]["retryable"] is True


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Week 1: Intro / Q&A", "Week 1 Intro Q&A"),
        ("  spaced\n title  ", "spaced title"),
        ("CON", "_CON"),
        ("...", "untitled"),
    ],
)
def test_safe_component(raw: str, expected: str) -> None:
    assert safe_component(raw) == expected


def test_output_path_must_stay_below_root(tmp_path: Path) -> None:
    root = tmp_path / "downloads"
    root.mkdir()
    assert ensure_within_root(root / "course" / "video.mp4", root).is_relative_to(root)

    with pytest.raises(PolicyError):
        ensure_within_root(tmp_path / "outside.mp4", root)


def test_symlink_guard_allows_root_alias_but_rejects_links_below_root(
    tmp_path: Path,
) -> None:
    actual_parent = tmp_path / "actual"
    root = actual_parent / "downloads"
    root.mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(actual_parent, target_is_directory=True)

    allowed = ensure_no_symlink_components(alias / "downloads" / "lecture", root)
    assert allowed == root / "lecture"

    internal = root / "linked"
    internal.symlink_to(root, target_is_directory=True)
    with pytest.raises(PolicyError) as caught:
        ensure_no_symlink_components(internal / "lecture", root)
    assert caught.value.code == "OUTPUT_SYMLINK_DENIED"


def test_sha256_file(tmp_path: Path) -> None:
    path = tmp_path / "artifact"
    path.write_bytes(b"panopto")
    assert sha256_file(path) == "f001fbda2311d4b51226775892d9a2b3634285351b9239547a81313c03b80dde"


def test_disk_reserve_guard_fails_before_space_is_consumed(tmp_path: Path) -> None:
    available = free_bytes(tmp_path)

    with pytest.raises(LocalIOError) as raised:
        require_free_space(tmp_path, available + 1)

    assert raised.value.code == "DISK_FULL"
    assert raised.value.exit_code == ExitCode.LOCAL_IO
