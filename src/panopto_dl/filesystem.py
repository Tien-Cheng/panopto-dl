"""Safe output paths, checksums, validation, and disk guards."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import unicodedata
from pathlib import Path
from typing import Final

from .errors import LocalIOError, PolicyError

_INVALID_COMPONENT: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f<>:\"/\\|?*]+")
_SPACE: Final[re.Pattern[str]] = re.compile(r"\s+")
_WINDOWS_NAMES: Final[set[str]] = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def safe_component(value: str, *, fallback: str = "untitled", max_length: int = 120) -> str:
    normalized = unicodedata.normalize("NFC", value)
    normalized = _INVALID_COMPONENT.sub(" ", normalized)
    normalized = _SPACE.sub(" ", normalized).strip(" .")
    if not normalized:
        normalized = fallback
    if normalized.upper() in _WINDOWS_NAMES:
        normalized = f"_{normalized}"
    if len(normalized) > max_length:
        normalized = normalized[:max_length].rstrip(" .")
    return normalized or fallback


def ensure_within_root(path: Path, root: Path) -> Path:
    resolved_root = root.expanduser().resolve()
    resolved = path.expanduser().resolve()
    if not resolved.is_relative_to(resolved_root):
        raise PolicyError("Output path is outside the configured root", code="OUTPUT_ROOT_DENIED")
    return resolved


def ensure_no_symlink_components(path: Path, root: Path) -> Path:
    """Reject symlinks in an output path before opening or replacing files."""

    resolved_root = root.expanduser().resolve()
    lexical_path = Path(os.path.abspath(path.expanduser()))
    resolved_path = lexical_path.resolve(strict=False)
    if not resolved_path.is_relative_to(resolved_root):
        raise PolicyError("Output path is outside the configured root", code="OUTPUT_ROOT_DENIED")

    matching_root_aliases = [
        candidate
        for candidate in (lexical_path, *lexical_path.parents)
        if candidate.resolve(strict=False) == resolved_root
    ]
    if not matching_root_aliases:
        raise PolicyError("Output path is outside the configured root", code="OUTPUT_ROOT_DENIED")
    lexical_root = min(matching_root_aliases, key=lambda candidate: len(candidate.parts))
    current = lexical_root
    for component in lexical_path.relative_to(lexical_root).parts:
        current /= component
        if current.is_symlink():
            raise PolicyError(
                "Output paths must not contain symbolic links",
                code="OUTPUT_SYMLINK_DENIED",
            )
    return resolved_path


def ensure_private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.chmod(0o700)
    return path


def free_bytes(path: Path) -> int:
    path.mkdir(parents=True, exist_ok=True)
    return shutil.disk_usage(path).free


def require_free_space(path: Path, reserve_bytes: int) -> int:
    available = free_bytes(path)
    if available < reserve_bytes:
        raise LocalIOError(
            "Free space is below the configured reserve",
            code="DISK_FULL",
            available_bytes=available,
            reserve_bytes=reserve_bytes,
        )
    return available


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def verify_media(path: Path, *, ffprobe: str = "ffprobe") -> dict[str, object]:
    command = [
        ffprobe,
        "-v",
        "error",
        "-show_entries",
        "format=duration,size,format_name",
        "-of",
        "json",
        str(path),
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LocalIOError("FFprobe could not validate the downloaded media") from exc
    if completed.returncode != 0:
        raise LocalIOError("Downloaded media failed FFprobe validation", code="MEDIA_INVALID")

    import json

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise LocalIOError(
            "FFprobe returned invalid validation data", code="MEDIA_INVALID"
        ) from exc
    return payload.get("format", {}) if isinstance(payload, dict) else {}
