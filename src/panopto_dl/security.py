"""Security helpers for URLs, filesystem state, and user-visible values.

This module is intentionally dependency-free.  It is imported by output code,
the browser boundary, and the yt-dlp adapter, so failures here must never echo
the value that failed validation.
"""

from __future__ import annotations

import os
import re
import stat
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit

from .errors import PolicyError

REDACTED: Final[str] = "[REDACTED]"

_PANOPTO_HOST_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|\.)(?:panopto\.com|panopto\.eu)$", re.IGNORECASE
)
_PANOPTO_STABLE_PAGE_RE: Final[re.Pattern[str]] = re.compile(
    r"/Panopto/Pages/(?P<page>Viewer|Embed|Sessions/List)\.aspx$", re.IGNORECASE
)
_URL_RE: Final[re.Pattern[str]] = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_ENCODED_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"https?(?:%3a%2f%2f|:\\/\\/|:\\u002f\\u002f)", re.IGNORECASE
)
_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?im)\b(?P<name>authorization|proxy-authorization|cookie|set-cookie|"
    r"x-panopto-[a-z0-9_-]*|x-csrf-token)\s*[:=]\s*[^\r\n]+"
)
_QUOTED_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?im)(?P<key_quote>['\"])(?P<name>authorization|proxy-authorization|cookie|"
    r"set-cookie|x-panopto-[a-z0-9_-]*|x-csrf-token)(?P=key_quote)\s*:\s*"
    r"(?P<value_quote>['\"])[^'\"\r\n]*(?P=value_quote)"
)
_AUTH_SCHEME_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?P<scheme>bearer|basic)\s+[A-Za-z0-9._~+/=-]+"
)
_SECRET_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:\b|\.)(?:access_token|auth(?:entication)?token|signature|sig|policy|"
    r"key-pair-id|x-amz-(?:credential|signature|security-token)|token|aspxauth|"
    r"fedauth|rtfa|panoptoauth|arraffinity(?:samesite)?)\s*="
    r"\s*[^&\s;,]+"
)
_SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "authenticated_body",
        "authenticated_response",
        "body",
        "browser_dir",
        "browser_path",
        "browser_profile",
        "browser_profile_dir",
        "browser_profile_path",
        "cookie",
        "cookie_file",
        "cookie_path",
        "cookiefile",
        "cookies",
        "headers",
        "http_headers",
        "password",
        "proxy_authorization",
        "raw_response",
        "response",
        "response_body",
        "response_content",
        "response_headers",
        "set_cookie",
        "signed_url",
        "stream_url",
        "token",
        "user_data_dir",
    }
)
_SECRET_KEY_PARTS: Final[frozenset[str]] = frozenset(
    {
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
)
_BROWSER_LOCATION_PARTS: Final[frozenset[str]] = frozenset(
    {
        "data",
        "dir",
        "directory",
        "directories",
        "dirs",
        "path",
        "paths",
        "profile",
        "profiles",
        "root",
        "roots",
        "state",
    }
)
_RESPONSE_PAYLOAD_PARTS: Final[frozenset[str]] = frozenset(
    {"body", "content", "data", "headers", "json", "payload", "raw", "text"}
)


def _canonical_hostname(hostname: str) -> str:
    try:
        return hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise PolicyError("Panopto site hostname is invalid", code="SITE_NOT_ALLOWED") from exc


def normalize_panopto_site(site: str) -> str:
    """Validate a configured Panopto site and return its HTTPS origin.

    Profiles may spell the site as an origin or include the conventional
    ``/Panopto`` suffix.  Credentials, query strings, fragments, non-HTTPS
    schemes, and non-Panopto hostnames are rejected.
    """

    try:
        parsed = urlsplit(site.strip())
        port = parsed.port
    except (AttributeError, ValueError) as exc:
        raise PolicyError("Panopto site is invalid", code="SITE_NOT_ALLOWED") from exc

    hostname = _canonical_hostname(parsed.hostname or "")
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or not _PANOPTO_HOST_RE.search(hostname)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") not in {"", "/Panopto"}
        or port not in {None, 443}
    ):
        raise PolicyError("Panopto site is not an allowed HTTPS origin", code="SITE_NOT_ALLOWED")

    return f"https://{hostname}"


def validate_allowed_url(url: str, site: str) -> str:
    """Return ``url`` after proving it belongs to the configured site."""

    origin = normalize_panopto_site(site)
    expected = urlsplit(origin)
    try:
        parsed = urlsplit(url.strip())
        port = parsed.port
    except (AttributeError, ValueError) as exc:
        raise PolicyError("Panopto URL is invalid", code="SITE_NOT_ALLOWED") from exc

    try:
        hostname = _canonical_hostname(parsed.hostname or "")
    except PolicyError as exc:
        raise PolicyError(
            "URL does not belong to the configured Panopto site", code="SITE_NOT_ALLOWED"
        ) from exc
    if (
        parsed.scheme.lower() != "https"
        or hostname != expected.hostname
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or any(ord(character) < 32 for character in url)
    ):
        raise PolicyError(
            "URL does not belong to the configured Panopto site", code="SITE_NOT_ALLOWED"
        )
    return url.strip()


def canonical_uuid(value: str) -> str:
    """Validate and normalize a Panopto public identifier."""

    try:
        parsed = uuid.UUID(value.strip())
    except (AttributeError, ValueError) as exc:
        raise PolicyError("Panopto identifier is invalid", code="INVALID_PANOPTO_ID") from exc
    return str(parsed)


def viewer_url(site: str, session_id: str) -> str:
    """Build the only session URL shape that may cross the engine boundary."""

    origin = normalize_panopto_site(site)
    return f"{origin}/Panopto/Pages/Viewer.aspx?{urlencode({'id': canonical_uuid(session_id)})}"


def folder_url(site: str, folder_id: str | None = None) -> str:
    """Build a stable root or folder URL without retaining caller parameters."""

    origin = normalize_panopto_site(site)
    base = f"{origin}/Panopto/Pages/Sessions/List.aspx"
    if folder_id is None:
        return base
    identifier = canonical_uuid(folder_id)
    fragment_value = quote(f'"{identifier}"')
    return f"{base}#folderID={fragment_value}"


def _stable_panopto_url(parsed_url: str) -> str | None:
    """Return a canonical public Viewer/Embed/List URL when possible."""

    try:
        parsed = urlsplit(parsed_url)
        port = parsed.port
    except ValueError:
        return None
    match = _PANOPTO_STABLE_PAGE_RE.search(parsed.path)
    try:
        hostname = _canonical_hostname(parsed.hostname or "")
    except PolicyError:
        return None
    if (
        not match
        or not hostname
        or not _PANOPTO_HOST_RE.search(hostname)
        or parsed.scheme.lower() != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
    ):
        return None

    origin = urlunsplit(("https", hostname, "", "", ""))
    page = match.group("page").lower()
    if page in {"viewer", "embed"}:
        query = parse_qs(parsed.query, keep_blank_values=False)
        for key in ("id", "pid"):
            values = query.get(key)
            if not values:
                continue
            try:
                identifier = canonical_uuid(values[0])
            except PolicyError:
                continue
            return f"{origin}{parsed.path}?{urlencode({key: identifier})}"
        return f"{origin}{parsed.path}"

    fragment = parse_qs(parsed.fragment, keep_blank_values=False)
    values = fragment.get("folderID")
    if values:
        try:
            identifier = canonical_uuid(values[0].strip('"'))
        except PolicyError:
            pass
        else:
            fragment_value = quote(f'"{identifier}"')
            return f"{origin}{parsed.path}#folderID={fragment_value}"
    return f"{origin}{parsed.path}"


def redact_url(value: str) -> str:
    """Remove bearer material from a URL while retaining stable Panopto IDs."""

    stable = _stable_panopto_url(value)
    if stable is not None:
        return stable
    try:
        parsed = urlsplit(value)
        port_number = parsed.port
    except ValueError:
        return REDACTED
    try:
        hostname = _canonical_hostname(parsed.hostname or "")
    except PolicyError:
        return REDACTED
    if (
        parsed.scheme.lower() == "https"
        and _PANOPTO_HOST_RE.search(hostname)
        and parsed.username is None
        and parsed.password is None
        and port_number in {None, 443}
        and parsed.path.rstrip("/") in {"", "/Panopto"}
        and not parsed.query
        and not parsed.fragment
    ):
        suffix = "/Panopto" if parsed.path.rstrip("/") == "/Panopto" else ""
        return f"https://{hostname}{suffix}"
    if not parsed.scheme or not parsed.hostname:
        return REDACTED
    port = f":{port_number}" if port_number not in {None, 80, 443} else ""
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{port}/{REDACTED}"


class Redactor:
    """Best-effort defense for messages from external browser/media libraries."""

    def __init__(self, secret_paths: tuple[str | Path, ...] = ()) -> None:
        self._secret_paths = tuple(
            sorted(
                (str(Path(path).expanduser()) for path in secret_paths if str(path)),
                key=len,
                reverse=True,
            )
        )

    def text(self, value: object) -> str:
        text = str(value)
        if _ENCODED_URL_RE.search(text):
            return REDACTED
        for path in self._secret_paths:
            text = text.replace(path, REDACTED)
        text = _QUOTED_HEADER_RE.sub(
            lambda match: (
                f"{match.group('key_quote')}{match.group('name')}"
                f"{match.group('key_quote')}: {match.group('value_quote')}"
                f"{REDACTED}{match.group('value_quote')}"
            ),
            text,
        )
        text = _HEADER_RE.sub(lambda match: f"{match.group('name')}: {REDACTED}", text)
        text = _AUTH_SCHEME_RE.sub(lambda match: f"{match.group('scheme')}: {REDACTED}", text)
        text = _SECRET_ASSIGNMENT_RE.sub(
            lambda match: match.group(0).split("=", 1)[0] + f"={REDACTED}", text
        )
        text = _URL_RE.sub(lambda match: redact_url(match.group(0).rstrip(".,);]")), text)
        return text


def redact_text(value: object, *, secret_paths: tuple[str | Path, ...] = ()) -> str:
    return Redactor(secret_paths).text(value)


def _normalized_key(value: str) -> str:
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", camel_split.casefold()).strip("_")


def _sensitive_output_key(key: str, ancestors: tuple[str, ...]) -> bool:
    parts = frozenset(part for part in key.split("_") if part)
    ancestor_parts = frozenset(
        part for ancestor in ancestors for part in ancestor.split("_") if part
    )
    if key in _SENSITIVE_KEYS or parts & _SECRET_KEY_PARTS:
        return True
    if ({"browser", "playwright"} & parts) and parts & _BROWSER_LOCATION_PARTS:
        return True
    if ({"browser", "playwright"} & ancestor_parts) and parts & _BROWSER_LOCATION_PARTS:
        return True
    if "response" in parts and parts & _RESPONSE_PAYLOAD_PARTS:
        return True
    return bool(
        ({"response", "authenticated"} & ancestor_parts) and parts & _RESPONSE_PAYLOAD_PARTS
    )


def redact_value(
    value: Any,
    *,
    _key: str | None = None,
    _ancestors: tuple[str, ...] = (),
) -> Any:
    """Recursively sanitize a value before JSON, logs, or persistence.

    Paths are kept by default because completed download paths are part of the
    agent contract.  Keys specifically associated with browser or cookie state
    are removed.
    """

    normalized_key = _normalized_key(_key or "")
    if _sensitive_output_key(normalized_key, _ancestors):
        return REDACTED
    if isinstance(value, Mapping):
        next_ancestors = (*_ancestors, normalized_key) if normalized_key else _ancestors
        return {
            str(key): redact_value(item, _key=str(key), _ancestors=next_ancestors)
            for key, item in value.items()
        }
    next_ancestors = (*_ancestors, normalized_key) if normalized_key else _ancestors
    if isinstance(value, list):
        return [redact_value(item, _ancestors=next_ancestors) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item, _ancestors=next_ancestors) for item in value)
    if isinstance(value, set):
        return {redact_value(item, _ancestors=next_ancestors) for item in value}
    if isinstance(value, str):
        if normalized_key.endswith("url") or value.lower().startswith(("http://", "https://")):
            return redact_url(value)
        return redact_text(value)
    return value


def ensure_private_directory(path: Path) -> Path:
    """Create an owner-only, non-symlink directory and verify its ownership."""

    expanded = path.expanduser()
    if expanded.is_symlink():
        raise PolicyError("Browser profile directory must not be a symlink", code="UNSAFE_PROFILE")
    expanded.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not expanded.is_dir():
        raise PolicyError("Browser profile path is not a directory", code="UNSAFE_PROFILE")

    if os.name != "nt":
        expanded.chmod(0o700)
        details = expanded.stat()
        if hasattr(os, "getuid") and details.st_uid != os.getuid():
            raise PolicyError(
                "Browser profile directory has an unsafe owner", code="UNSAFE_PROFILE"
            )
        if stat.S_IMODE(details.st_mode) & 0o077:
            raise PolicyError(
                "Browser profile directory permissions are unsafe", code="UNSAFE_PROFILE"
            )
    return expanded.resolve()


def ensure_private_file(path: Path) -> Path:
    """Force a cookie file to owner-read/write and reject links/non-files."""

    if path.is_symlink() or not path.is_file():
        raise PolicyError("Cookie file is unsafe", code="UNSAFE_COOKIE_FILE")
    if os.name != "nt":
        path.chmod(0o600)
        details = path.stat()
        if hasattr(os, "getuid") and details.st_uid != os.getuid():
            raise PolicyError("Cookie file has an unsafe owner", code="UNSAFE_COOKIE_FILE")
        if stat.S_IMODE(details.st_mode) & 0o077:
            raise PolicyError("Cookie file permissions are unsafe", code="UNSAFE_COOKIE_FILE")
    return path.resolve()


__all__ = [
    "REDACTED",
    "Redactor",
    "canonical_uuid",
    "ensure_private_directory",
    "ensure_private_file",
    "folder_url",
    "normalize_panopto_site",
    "redact_text",
    "redact_url",
    "redact_value",
    "validate_allowed_url",
    "viewer_url",
]
