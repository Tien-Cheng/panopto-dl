"""Interactive browser authentication with an ephemeral cookie boundary."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager, suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote

from .errors import AuthenticationError, LocalIOError, RemoteError, UsageError
from .security import (
    Redactor,
    ensure_private_directory,
    ensure_private_file,
    folder_url,
    normalize_panopto_site,
)


@dataclass(frozen=True, slots=True)
class AuthResult:
    """Secret-free result returned by every authentication operation."""

    authenticated: bool
    site: str
    checked_at: datetime
    reason: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@runtime_checkable
class BrowserSessionBoundary(Protocol):
    """Boundary consumed by the CLI and scheduler."""

    def login(self, timeout_seconds: float = 900) -> AuthResult: ...

    def status(self) -> AuthResult: ...

    def logout(self) -> AuthResult: ...

    def cookies_file(self, *, headless: bool = True) -> AbstractContextManager[Path]: ...


class BrowserSession:
    """A dedicated persistent Playwright profile for one Panopto site.

    Playwright drives an already-installed system Chrome or Chromium.  It does
    not install or silently fall back to Playwright's bundled browser.  Login is
    always interactive; credentials and MFA values never enter this API.
    """

    _LOGIN_POLL_SECONDS = 1.0

    def __init__(
        self,
        base_url: str,
        profile_dir: Path,
        browser_executable: Path | None = None,
        browser_channel: str | None = "chrome",
        *,
        launch_timeout_seconds: float = 30,
    ) -> None:
        self.base_url = normalize_panopto_site(base_url)
        self._profile_dir = ensure_private_directory(profile_dir)
        self._browser_executable = (
            browser_executable.expanduser().resolve() if browser_executable is not None else None
        )
        self._browser_channel = browser_channel.strip() if browser_channel else None
        self._launch_timeout_ms = int(launch_timeout_seconds * 1000)
        if self._launch_timeout_ms <= 0:
            raise UsageError("Browser launch timeout must be positive")
        self._redactor = Redactor((self._profile_dir,))

    def login(self, timeout_seconds: float = 900) -> AuthResult:
        """Open a headed browser and wait for a verified Panopto API session."""

        if timeout_seconds <= 0:
            raise UsageError("Authentication timeout must be positive")
        with self._open_context(headless=False) as context:
            page = context.pages[0] if context.pages else context.new_page()
            with suppress(Exception):
                page.goto(folder_url(self.base_url), wait_until="domcontentloaded")
                # SSO pages can interrupt navigation while still leaving a usable
                # interactive tab.  Authentication is decided only by the probe.

            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                if self._probe_authenticated(context):
                    return self._result(True, "AUTHENTICATED")
                if self._context_closed(context):
                    break
                time.sleep(min(self._LOGIN_POLL_SECONDS, max(0.0, deadline - time.monotonic())))
        return self._result(False, "AUTH_REQUIRED")

    def status(self) -> AuthResult:
        """Verify the persisted session headlessly using Panopto folder data."""

        with self._open_context(headless=True) as context:
            authenticated = self._probe_authenticated(context)
        return self._result(authenticated, "AUTHENTICATED" if authenticated else "AUTH_REQUIRED")

    def logout(self) -> AuthResult:
        """Clear cookies and site storage inside the dedicated profile."""

        with self._open_context(headless=True) as context:
            try:
                context.clear_cookies()
                page = context.pages[0] if context.pages else context.new_page()
                page.goto(self.base_url, wait_until="domcontentloaded")
                page.evaluate(
                    """() => {
                        try { window.localStorage.clear(); } catch (_) {}
                        try { window.sessionStorage.clear(); } catch (_) {}
                    }"""
                )
            except Exception:
                raise LocalIOError(
                    "The dedicated browser session could not be cleared",
                    code="BROWSER_LOGOUT_FAILED",
                ) from None
        return self._result(False, "SIGNED_OUT")

    @contextmanager
    def cookies_file(self, *, headless: bool = True) -> Iterator[Path]:
        """Yield an authenticated 0600 Netscape cookie file, then delete it."""

        cookie_path: Path | None = None
        with self._open_context(headless=headless) as context:
            if not self._probe_authenticated(context):
                raise AuthenticationError()
            cookies = context.cookies([self.base_url])
            cookie_path = self._write_cookie_file(cookies)

        try:
            yield cookie_path
        finally:
            if cookie_path is not None:
                try:
                    cookie_path.unlink(missing_ok=True)
                except OSError:
                    # The value is a short-lived bearer credential.  A failure to
                    # remove it is surfaced without printing its temporary path.
                    raise LocalIOError(
                        "Temporary authentication state could not be removed",
                        code="COOKIE_CLEANUP_FAILED",
                    ) from None

    def _result(self, authenticated: bool, reason: str) -> AuthResult:
        return AuthResult(authenticated, self.base_url, datetime.now(UTC), reason)

    @staticmethod
    def _validate_executable(value: Path | None) -> Path | None:
        if value is None:
            return None
        executable = value.expanduser().resolve()
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise UsageError(
                "Configured browser executable is unavailable", code="BROWSER_UNAVAILABLE"
            )
        return executable

    @contextmanager
    def _open_context(self, *, headless: bool) -> Iterator[Any]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise LocalIOError("Playwright is not installed", code="BROWSER_UNAVAILABLE") from None

        with sync_playwright() as playwright:
            context = None
            for candidate_type, candidate_value in self._launch_candidates():
                try:
                    if candidate_type == "channel":
                        context = playwright.chromium.launch_persistent_context(
                            user_data_dir=self._profile_dir,
                            headless=headless,
                            timeout=self._launch_timeout_ms,
                            accept_downloads=False,
                            channel=candidate_value,
                        )
                    else:
                        context = playwright.chromium.launch_persistent_context(
                            user_data_dir=self._profile_dir,
                            headless=headless,
                            timeout=self._launch_timeout_ms,
                            accept_downloads=False,
                            executable_path=candidate_value,
                        )
                    break
                except Exception:
                    continue
            if context is None:
                raise LocalIOError(
                    "System Chrome or Chromium could not open the dedicated profile",
                    code="BROWSER_UNAVAILABLE",
                    retryable=True,
                )
            try:
                yield context
            finally:
                with suppress(Exception):
                    context.close()

    def _launch_candidates(self) -> tuple[tuple[str, str], ...]:
        if self._browser_executable is not None:
            executable = self._validate_executable(self._browser_executable)
            assert executable is not None
            return (("executable", str(executable)),)

        candidates: list[tuple[str, str]] = []
        if self._browser_channel:
            candidates.append(("channel", self._browser_channel))

        seen: set[Path] = set()
        for executable in _installed_browser_paths():
            resolved = executable.expanduser().resolve()
            if resolved in seen or not resolved.is_file() or not os.access(resolved, os.X_OK):
                continue
            seen.add(resolved)
            candidates.append(("executable", str(resolved)))
        if not candidates:
            raise LocalIOError(
                "No supported system Chrome or Chromium installation was found",
                code="BROWSER_UNAVAILABLE",
            )
        return tuple(candidates)

    def _probe_authenticated(self, context: Any) -> bool:
        endpoint = f"{self.base_url}/Panopto/Services/Data.svc/GetSessions"
        payload = {
            "queryParameters": {
                "sortColumn": 1,
                "getFolderData": True,
                "includePlaylists": True,
                "page": 0,
                "maxResults": 1,
            }
        }
        try:
            response = context.request.post(
                endpoint,
                data=payload,
                headers={"accept": "application/json", "content-type": "application/json"},
                timeout=15_000,
            )
        except Exception:
            raise RemoteError(
                "Panopto authentication could not be verified",
                code="AUTH_CHECK_FAILED",
                retryable=True,
            ) from None

        if response.status in {401, 403}:
            return False
        if response.status >= 500:
            raise RemoteError(
                "Panopto authentication could not be verified",
                code="AUTH_CHECK_FAILED",
                retryable=True,
            )
        try:
            body = response.json()
        except Exception:
            return False
        body = _unwrap_panopto_json(body)
        if not isinstance(body, Mapping):
            return False
        if body.get("ErrorCode") == 2:
            return False
        if body.get("ErrorCode") is not None:
            raise RemoteError(
                "Panopto rejected the authentication check",
                code="AUTH_CHECK_FAILED",
                retryable=True,
            )
        has_session_shape = any(
            key in body
            for key in ("Results", "Subfolders", "TotalResultCount", "TotalNumber", "MoreData")
        )
        if not has_session_shape:
            return False
        try:
            return bool(context.cookies([self.base_url]))
        except Exception:
            raise RemoteError(
                "Panopto authentication could not be verified",
                code="AUTH_CHECK_FAILED",
                retryable=True,
            ) from None

    @staticmethod
    def _context_closed(context: Any) -> bool:
        try:
            return not context.pages
        except Exception:
            return True

    @staticmethod
    def _write_cookie_file(cookies: list[Mapping[str, Any]]) -> Path:
        descriptor, raw_path = tempfile.mkstemp(prefix="panopto-dl-", suffix=".cookies.txt")
        path = Path(raw_path)
        try:
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write("# Netscape HTTP Cookie File\n")
                handle.write("# This file is temporary. Do not copy or persist it.\n\n")
                for cookie in cookies:
                    line = _netscape_cookie_line(cookie)
                    if line is not None:
                        handle.write(line)
                        handle.write("\n")
            return ensure_private_file(path)
        except Exception:
            with suppress(OSError):
                os.close(descriptor)
            path.unlink(missing_ok=True)
            raise


def _unwrap_panopto_json(value: object) -> object:
    current = value
    for _ in range(2):
        if isinstance(current, Mapping) and set(current) == {"d"}:
            current = current["d"]
        if isinstance(current, str):
            try:
                current = json.loads(current)
            except json.JSONDecodeError:
                return current
    return current


def _netscape_cookie_line(cookie: Mapping[str, Any]) -> str | None:
    domain = str(cookie.get("domain") or "").strip()
    name = str(cookie.get("name") or "")
    if not domain or not name or any(character in name for character in "\t\r\n"):
        return None
    include_subdomains = domain.startswith(".")
    if bool(cookie.get("httpOnly")):
        domain = f"#HttpOnly_{domain}"
    path = str(cookie.get("path") or "/").replace("\t", "%09").replace("\n", "%0A")
    value = str(cookie.get("value") or "")
    value = quote(value, safe="!#$%&'()*+-./:<=>?@[]^_`{|}~")
    expires_raw = cookie.get("expires")
    try:
        expires = max(0, int(float(expires_raw))) if expires_raw is not None else 0
    except (TypeError, ValueError):
        expires = 0
    fields = (
        domain,
        "TRUE" if include_subdomains else "FALSE",
        path,
        "TRUE" if bool(cookie.get("secure")) else "FALSE",
        str(expires),
        name,
        value,
    )
    return "\t".join(fields)


def _installed_browser_paths() -> tuple[Path, ...]:
    names = ("google-chrome-stable", "google-chrome", "chromium", "chromium-browser")
    discovered = [Path(found) for name in names if (found := shutil.which(name))]
    discovered.extend(
        [
            Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
            Path("/usr/bin/google-chrome-stable"),
            Path("/usr/bin/google-chrome"),
            Path("/usr/bin/chromium"),
            Path("/usr/bin/chromium-browser"),
        ]
    )
    return tuple(discovered)


def browser_available(executable: Path | None = None) -> bool:
    """Return whether a configured or conventional system browser is executable."""

    candidates = (executable,) if executable is not None else _installed_browser_paths()
    return any(
        candidate is not None
        and candidate.expanduser().is_file()
        and os.access(candidate.expanduser(), os.X_OK)
        for candidate in candidates
    )


__all__ = ["AuthResult", "BrowserSession", "BrowserSessionBoundary", "browser_available"]
