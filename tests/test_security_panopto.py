from __future__ import annotations

import json
import os
import stat
from contextlib import nullcontext
from pathlib import Path
from typing import Any

import pytest

from panopto_dl.browser import BrowserSession
from panopto_dl.domain import MediaPolicy, SessionState
from panopto_dl.errors import AuthenticationError, PolicyError, RemoteError
from panopto_dl.panopto import (
    PanoptoClient,
    ProgressEvent,
    _assert_local_ffmpeg_paths,
    _default_ydl_factory,
)
from panopto_dl.security import (
    REDACTED,
    ensure_private_directory,
    folder_url,
    normalize_panopto_site,
    redact_text,
    redact_value,
    validate_allowed_url,
)

SITE = "https://mediaweb.ap.panopto.com"
SESSION_ID = "26b3ae9e-4a48-4dcc-96ba-0befba08a0fb"
FOLDER_ID = "e4c6a2fc-1214-4ca0-8fb7-aef2e29ff63a"
CHILD_FOLDER_ID = "1699b71f-5c41-478b-b6cd-af6f011c29c7"


def _cookie_file(tmp_path: Path) -> Path:
    path = tmp_path / "cookies.txt"
    path.write_text("# Netscape HTTP Cookie File\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _session_info(*, composite: bool = False) -> dict[str, Any]:
    formats: list[dict[str, Any]]
    if composite:
        formats = [
            {
                "format_id": "audio",
                "ext": "m4a",
                "protocol": "https",
                "vcodec": "none",
                "acodec": "mp4a.40.2",
                "url": "https://cdn.example.invalid/audio?Signature=audio-secret",
            },
            {
                "format_id": "slides",
                "ext": "mhtml",
                "protocol": "mhtml",
                "vcodec": "none",
                "acodec": "none",
                "url": "about:invalid",
                "fragments": [{"url": "https://cdn.invalid/slide?token=slide-secret"}],
            },
        ]
    else:
        formats = [
            {
                "format_id": "hls-720",
                "ext": "mp4",
                "protocol": "m3u8_native",
                "vcodec": "avc1.4d401f",
                "acodec": "mp4a.40.2",
                "height": 720,
                "filesize_approx": 1234,
                "format_note": "PODCAST",
                "url": "https://cdn.example.invalid/master.m3u8?Signature=stream-secret",
                "http_headers": {"Cookie": "auth=header-secret"},
            }
        ]
    return {
        "id": SESSION_ID,
        "title": "Lecture 1",
        "description": "Slides at https://cdn.invalid/file?token=description-secret",
        "timestamp": 1_725_000_000,
        "duration": 3600.5,
        "uploader": "Lecturer",
        "channel_id": FOLDER_ID,
        "channel": "Course folder",
        "formats": formats,
        "subtitles": {
            "en-US": [
                {
                    "ext": "srt",
                    "url": "https://cdn.invalid/captions?token=subtitle-secret",
                }
            ]
        },
        "chapters": [{"title": "Introduction", "start_time": 0, "end_time": 30}],
        "thumbnail": "https://cdn.invalid/image?token=thumbnail-secret",
    }


class FakeYDL:
    def __init__(
        self,
        factory: FakeYDLFactory,
        options: dict[str, Any],
    ) -> None:
        self.factory = factory
        self.options = options

    def __enter__(self) -> FakeYDL:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def extract_info(self, url: str, *, download: bool) -> dict[str, Any]:
        self.factory.calls.append((url, download, self.options))
        if self.factory.error is not None:
            raise self.factory.error
        result = (
            self.factory.results.pop(0)
            if len(self.factory.results) > 1
            else self.factory.results[0]
        )
        if download:
            self._materialize_download(result)
        return result

    def _materialize_download(self, result: dict[str, Any]) -> None:
        template = self.options["outtmpl"]["default"]
        selector = self.options["format"]
        if "," in selector:
            for format_id, extension in (("audio", "m4a"), ("slides", "mhtml")):
                filename = template.replace("%(format_id)s", format_id).replace(
                    "%(ext)s", extension
                )
                Path(filename).write_bytes(b"asset")
        else:
            filename = template.replace("%(format_id)s", "hls-720").replace("%(ext)s", "mp4")
            Path(filename).write_bytes(b"media")
        for hook in self.options["progress_hooks"]:
            hook(
                {
                    "status": "downloading",
                    "filename": "/tmp/lecture.mp4?token=progress-secret",
                    "downloaded_bytes": 5,
                    "total_bytes": 10,
                }
            )


class FakeYDLFactory:
    def __init__(self, *results: dict[str, Any], error: Exception | None = None) -> None:
        self.results = list(results) or [_session_info()]
        self.error = error
        self.calls: list[tuple[str, bool, dict[str, Any]]] = []

    def __call__(self, options: dict[str, Any]) -> FakeYDL:
        return FakeYDL(self, options)


@pytest.mark.parametrize("message", ["HTTP Error 401: Unauthorized", "HTTP Error 403"])
def test_authorization_failures_request_fresh_authentication(tmp_path: Path, message: str) -> None:
    client = PanoptoClient(
        SITE,
        _cookie_file(tmp_path),
        tmp_path,
        ydl_factory=FakeYDLFactory(error=RuntimeError(message)),
    )

    with pytest.raises(AuthenticationError):
        client.inspect(SESSION_ID)


def test_panopto_site_and_url_allow_list() -> None:
    assert normalize_panopto_site(f"{SITE}/Panopto/") == SITE
    assert validate_allowed_url(f"{SITE}/Panopto/Pages/Viewer.aspx?id={SESSION_ID}", SITE)

    for value in (
        "http://mediaweb.ap.panopto.com",
        "https://mediaweb.ap.panopto.com.evil.example",
        "https://user:pass@mediaweb.ap.panopto.com",
        "https://demo.hosted.panopto.com/Panopto/Pages/Viewer.aspx?id=" + SESSION_ID,
    ):
        with pytest.raises(PolicyError):
            validate_allowed_url(value, SITE)


def test_embed_pid_is_canonicalized_to_a_stable_viewer_url(tmp_path: Path) -> None:
    factory = FakeYDLFactory(_session_info())
    client = PanoptoClient(
        SITE,
        _cookie_file(tmp_path),
        tmp_path / "downloads",
        ydl_factory=factory,
    )

    session = client.inspect(f"{SITE}/Panopto/Pages/Embed.aspx?pid={SESSION_ID}&token=discarded")

    assert session.url == f"{SITE}/Panopto/Pages/Viewer.aspx?id={SESSION_ID}"
    assert factory.calls[0][0] == session.url


def test_stable_urls_preserve_only_public_identifiers() -> None:
    value = (
        f"{SITE}/Panopto/Pages/Viewer.aspx?id={SESSION_ID}"
        "&auth=secret&Signature=also-secret#token=fragment-secret"
    )
    redacted = redact_text(value)
    assert redacted == f"{SITE}/Panopto/Pages/Viewer.aspx?id={SESSION_ID}"
    assert redact_text(SITE) == SITE
    assert "secret" not in redacted
    assert folder_url(SITE, FOLDER_ID).endswith(f"folderID=%22{FOLDER_ID}%22")


def test_redaction_never_raises_for_an_invalid_unicode_hostname() -> None:
    unsafe = "https://" + chr(0xD800) + ".invalid/path?token=secret"

    assert redact_text(unsafe) == REDACTED


@pytest.mark.parametrize(
    "encoded",
    [
        "https%3A%2F%2Fcdn.invalid%2Fvideo%3FSignature%3DENCODED_SECRET",
        r"https:\/\/cdn.invalid/video?Signature=ESCAPED_SECRET",
        r"https:\u002f\u002fcdn.invalid/video?Signature=UNICODE_ESCAPE_SECRET",
    ],
)
def test_redaction_removes_encoded_or_escaped_transport_urls(encoded: str) -> None:
    assert redact_text(encoded) == REDACTED


def test_redaction_removes_common_bearer_cookie_assignments() -> None:
    rendered = redact_text(".ASPXAUTH=secret; FedAuth=other-secret")

    assert "secret" not in rendered
    assert rendered.count(REDACTED) == 2


def test_redaction_removes_python_and_json_header_representations() -> None:
    rendered = redact_text(
        "{'Authorization': 'Bearer PY_REPR_SECRET', "
        '"Cookie": "session=COOKIE_REPR_SECRET", '
        "'X-Panopto-Token': 'PANOPTO_REPR_SECRET'}"
    )

    assert "PY_REPR_SECRET" not in rendered
    assert "COOKIE_REPR_SECRET" not in rendered
    assert "PANOPTO_REPR_SECRET" not in rendered


def test_recursive_redaction_removes_headers_cookies_and_signed_urls(tmp_path: Path) -> None:
    browser_path = tmp_path / "browser" / "Default"
    value = {
        "viewer_url": f"{SITE}/Panopto/Pages/Viewer.aspx?id={SESSION_ID}&token=secret",
        "stream_url": "https://cdn.invalid/video?Signature=signed-secret",
        "headers": {"Authorization": "Bearer secret", "Cookie": "auth=secret"},
        "browser_profile_dir": str(browser_path),
        "browserProfilePath": str(browser_path),
        "browserProfileDirectory": str(browser_path),
        "userDataDir": str(browser_path),
        "playwrightProfilePath": str(browser_path),
        "cookieJar": "cookie-secret",
        "authenticatedResponse": {"body": "private-response"},
        "responseText": "private-response-text",
        "message": "Cookie: auth=secret\nAuthorization: Bearer other-secret",
    }
    rendered = json.dumps(redact_value(value))
    assert SESSION_ID in rendered
    assert "signed-secret" not in rendered
    assert "cookie-secret" not in rendered
    assert "other-secret" not in rendered
    assert str(browser_path) not in rendered
    assert "private-response" not in rendered
    assert rendered.count(REDACTED) >= 3


def test_private_directory_rejects_links_and_has_owner_only_mode(tmp_path: Path) -> None:
    profile = ensure_private_directory(tmp_path / "profile")
    if os.name != "nt":
        assert stat.S_IMODE(profile.stat().st_mode) == 0o700

    linked = tmp_path / "linked"
    linked.symlink_to(profile, target_is_directory=True)
    with pytest.raises(PolicyError, match="symlink"):
        ensure_private_directory(linked)


class _FakeResponse:
    status = 200

    def __init__(self, body: dict[str, Any] | None = None) -> None:
        self._body = body if body is not None else {"d": {"Results": [], "Subfolders": []}}

    def json(self) -> dict[str, Any]:
        return self._body


class _FakeRequest:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response

    def post(self, *_args: object, **_kwargs: object) -> _FakeResponse:
        return self._response


class _FakeContext:
    def __init__(
        self,
        *,
        response_body: dict[str, Any] | None = None,
        cookies: list[dict[str, Any]] | None = None,
    ) -> None:
        self.request = _FakeRequest(_FakeResponse(response_body))
        self.pages: list[object] = []
        self.cookie_urls: list[str] | None = None
        self._cookies = cookies if cookies is not None else [
            {
                "domain": ".ap.panopto.com",
                "name": ".ASPXAUTH",
                "value": "cookie-secret",
                "path": "/",
                "secure": True,
                "httpOnly": True,
                "expires": -1,
            }
        ]

    def cookies(self, urls: list[str]) -> list[dict[str, Any]]:
        self.cookie_urls = urls
        return self._cookies


def test_browser_status_rejects_results_without_session_cookies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    browser = BrowserSession(SITE, tmp_path / "browser", browser_channel=None)
    context = _FakeContext(
        response_body={"d": {"Results": [{"Id": SESSION_ID}], "TotalNumber": 1}},
        cookies=[],
    )
    monkeypatch.setattr(browser, "_open_context", lambda *, headless: nullcontext(context))

    status = browser.status()

    assert status.authenticated is False
    assert status.reason == "AUTH_REQUIRED"
    assert context.cookie_urls == [SITE]


def test_browser_status_rejects_results_with_only_analytics_cookies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    browser = BrowserSession(SITE, tmp_path / "browser", browser_channel=None)
    context = _FakeContext(
        response_body={"d": {"Results": [{"Id": SESSION_ID}], "TotalNumber": 1}},
        cookies=[
            {
                "domain": ".panopto.com",
                "name": name,
                "value": "analytics-value",
                "path": "/",
                "secure": False,
                "httpOnly": False,
                "expires": -1,
            }
            for name in ("_ga", "_gid")
        ],
    )
    monkeypatch.setattr(browser, "_open_context", lambda *, headless: nullcontext(context))

    status = browser.status()

    assert status.authenticated is False
    assert status.reason == "AUTH_REQUIRED"
    assert context.cookie_urls == [SITE]


def test_browser_status_accepts_results_with_http_only_session_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    browser = BrowserSession(SITE, tmp_path / "browser", browser_channel=None)
    context = _FakeContext(
        response_body={"d": {"Results": [{"Id": SESSION_ID}], "TotalNumber": 1}},
        cookies=[
            {
                "domain": ".ap.panopto.com",
                "name": "ASP.NET_SessionId",
                "value": "session-secret",
                "path": "/",
                "secure": True,
                "httpOnly": True,
                "expires": -1,
            }
        ],
    )
    monkeypatch.setattr(browser, "_open_context", lambda *, headless: nullcontext(context))

    status = browser.status()

    assert status.authenticated is True
    assert status.reason == "AUTHENTICATED"
    assert context.cookie_urls == [SITE]


def test_browser_status_and_cookie_export_are_secret_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    browser = BrowserSession(SITE, tmp_path / "browser", browser_channel=None)
    context = _FakeContext()
    monkeypatch.setattr(browser, "_open_context", lambda *, headless: nullcontext(context))

    status = browser.status()
    assert status.authenticated is True
    assert status.reason == "AUTHENTICATED"
    with browser.cookies_file() as cookie_path:
        assert cookie_path.exists()
        if os.name != "nt":
            assert stat.S_IMODE(cookie_path.stat().st_mode) == 0o600
        cookie_text = cookie_path.read_text(encoding="utf-8")
        assert cookie_text.startswith("# Netscape HTTP Cookie File")
        assert "#HttpOnly_.ap.panopto.com" in cookie_text
        assert "cookie-secret" in cookie_text
    assert not cookie_path.exists()
    assert "cookie-secret" not in json.dumps(status.as_dict(), default=str)


def test_inspect_returns_sanitized_dto_and_secure_yt_dlp_options(tmp_path: Path) -> None:
    factory = FakeYDLFactory(_session_info())
    client = PanoptoClient(
        SITE,
        _cookie_file(tmp_path),
        tmp_path / "downloads",
        ydl_factory=factory,
    )

    session = client.inspect(SESSION_ID)
    rendered = json.dumps(session.as_dict(), default=str)
    assert session.session_id == SESSION_ID
    assert session.url == f"{SITE}/Panopto/Pages/Viewer.aspx?id={SESSION_ID}"
    assert session.formats[0].format_id == "hls-720"
    assert session.subtitles[0].language == "en-US"
    for secret in (
        "stream-secret",
        "header-secret",
        "subtitle-secret",
        "thumbnail-secret",
        "description-secret",
    ):
        assert secret not in rendered

    options = factory.calls[0][2]
    assert options["mark_watched"] is False
    assert options["skip_download"] is True
    assert options["hls_prefer_native"] is True
    assert set(options["external_downloader"].values()) == {"native"}
    assert "ffmpeg" not in json.dumps(options, default=str).lower()


def test_discovery_separates_folders_and_sessions(tmp_path: Path) -> None:
    playlist = {
        "_type": "playlist",
        "id": FOLDER_ID,
        "title": "Course",
        "entries": [
            {
                "_type": "url",
                "ie_key": "PanoptoList",
                "id": CHILD_FOLDER_ID,
                "title": "Week 1",
                "url": folder_url(SITE, CHILD_FOLDER_ID),
            },
            {
                "_type": "url",
                "ie_key": "Panopto",
                "id": SESSION_ID,
                "title": "Lecture 1",
                "duration": 3600,
                "channel_id": FOLDER_ID,
                "channel": "Course",
                "url": f"{SITE}/Panopto/Pages/Viewer.aspx?id={SESSION_ID}&token=secret",
            },
        ],
    }
    folder_factory = FakeYDLFactory(playlist)
    folder_client = PanoptoClient(
        SITE,
        _cookie_file(tmp_path),
        tmp_path / "downloads",
        ydl_factory=folder_factory,
    )
    folders = folder_client.discover_folders(FOLDER_ID, recursive=False)
    sessions = folder_client.discover_sessions(FOLDER_ID, recursive=False)

    assert folders == [
        folders[0]
    ]  # keeps the assertion readable while checking one deduplicated result
    assert folders[0].folder_id == CHILD_FOLDER_ID
    assert folders[0].parent_id == FOLDER_ID
    assert sessions[0].session_id == SESSION_ID
    assert sessions[0].url == f"{SITE}/Panopto/Pages/Viewer.aspx?id={SESSION_ID}"


def test_download_uses_native_transport_and_only_safe_progress(tmp_path: Path) -> None:
    factory = FakeYDLFactory(_session_info(), _session_info())
    client = PanoptoClient(
        SITE,
        _cookie_file(tmp_path),
        tmp_path / "downloads",
        ydl_factory=factory,
    )
    events: list[ProgressEvent] = []
    destination = tmp_path / "downloads" / "course" / "lecture"

    result = client.download(SESSION_ID, destination, MediaPolicy.LECTURE, events.append)

    assert result.state == SessionState.COMPLETE
    assert (destination / "lecture.mp4").is_file()
    metadata = (destination / "metadata.json").read_text(encoding="utf-8")
    assert SESSION_ID in metadata
    assert "stream-secret" not in metadata
    assert "progress-secret" not in events[0].filename
    download_options = factory.calls[1][2]
    assert download_options["skip_download"] is False
    assert download_options["format"].startswith("b[format_note*=PODCAST]")
    assert set(download_options["external_downloader"].values()) == {"native"}
    assert download_options["concurrent_fragment_downloads"] == 1
    assert download_options["postprocessors"] == [
        {"key": "FFmpegVideoRemuxer", "preferedformat": "mp4"}
    ]


def test_audio_and_slides_are_preserved_as_needs_composite(tmp_path: Path) -> None:
    raw = _session_info(composite=True)
    factory = FakeYDLFactory(raw, raw)
    client = PanoptoClient(
        SITE,
        _cookie_file(tmp_path),
        tmp_path / "downloads",
        ydl_factory=factory,
    )
    destination = tmp_path / "downloads" / "course" / "slides-only"

    result = client.download(SESSION_ID, destination)

    assert result.state == SessionState.NEEDS_COMPOSITE
    assert (destination / "lecture.m4a").is_file()
    assert (destination / "slides.mhtml").is_file()
    assert factory.calls[1][2]["format"] == "audio,slides"


def test_download_rejects_a_preexisting_metadata_partial_symlink(tmp_path: Path) -> None:
    factory = FakeYDLFactory(_session_info(), _session_info())
    output_root = tmp_path / "downloads"
    destination = output_root / "course" / "lecture"
    destination.mkdir(parents=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("unchanged", encoding="utf-8")
    (destination / "metadata.json.part").symlink_to(victim)
    client = PanoptoClient(
        SITE,
        _cookie_file(tmp_path),
        output_root,
        ydl_factory=factory,
    )

    with pytest.raises(PolicyError) as caught:
        client.download(SESSION_ID, destination)

    assert caught.value.code == "OUTPUT_SYMLINK_DENIED"
    assert victim.read_text(encoding="utf-8") == "unchanged"
    assert factory.calls == []


def test_cross_site_url_is_rejected_before_yt_dlp(tmp_path: Path) -> None:
    factory = FakeYDLFactory(_session_info())
    client = PanoptoClient(
        SITE,
        _cookie_file(tmp_path),
        tmp_path / "downloads",
        ydl_factory=factory,
    )
    with pytest.raises(PolicyError):
        client.inspect(f"https://evil.example/Panopto/Pages/Viewer.aspx?id={SESSION_ID}")
    assert factory.calls == []


def test_external_failures_and_logs_never_expose_bearer_values(tmp_path: Path) -> None:
    cookie = _cookie_file(tmp_path)
    secret_url = "https://cdn.invalid/media?Signature=exception-secret"
    factory = FakeYDLFactory(error=RuntimeError(f"failed {secret_url} using {cookie}"))
    logs: list[str] = []
    client = PanoptoClient(
        SITE,
        cookie,
        tmp_path / "downloads",
        ydl_factory=factory,
        log_hook=lambda _level, message: logs.append(message),
    )

    with pytest.raises(RemoteError) as caught:
        client.inspect(SESSION_ID)
    rendered = str(caught.value)
    assert "exception-secret" not in rendered
    assert str(cookie) not in rendered

    logger = client._base_ydl_options()["logger"]
    logger.error(f"Cookie: auth=logger-secret\nURL {secret_url}")
    logger.error("headers={'Authorization': 'Bearer repr-logger-secret'}")
    assert "logger-secret" not in logs[0]
    assert "exception-secret" not in logs[0]
    assert "repr-logger-secret" not in logs[1]


def test_ffmpeg_guard_rejects_signed_network_input_before_child_process(
    tmp_path: Path,
) -> None:
    from yt_dlp.postprocessor.ffmpeg import FFmpegPostProcessor

    signed_url = "https://cdn.invalid/master.m3u8?Signature=ffmpeg-secret"
    child_process_inputs: list[str] = []

    class ProbeFFmpegPostProcessor(FFmpegPostProcessor):
        def real_run_ffmpeg(
            self,
            input_path_opts: list[tuple[str, list[str]]],
            output_path_opts: list[tuple[str, list[str]]],
            **_kwargs: object,
        ) -> str:
            child_process_inputs.extend(path for path, _options in input_path_opts)
            return ""

        def run(self, information: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
            self.real_run_ffmpeg(
                [(signed_url, [])],
                [(str(tmp_path / "lecture.mp4"), [])],
            )
            return [], information

    ydl = _default_ydl_factory({"quiet": True, "logger": None})
    try:
        processor = ProbeFFmpegPostProcessor(ydl)
        with pytest.raises(PolicyError) as caught:
            ydl.run_pp(processor, {})
    finally:
        ydl.close()

    assert caught.value.code == "FFMPEG_REMOTE_INPUT_DENIED"
    assert "ffmpeg-secret" not in str(caught.value)
    assert child_process_inputs == []


def test_ffmpeg_guard_accepts_only_existing_absolute_local_inputs(tmp_path: Path) -> None:
    input_path = (tmp_path / "input.mp4").resolve()
    input_path.write_bytes(b"local")
    output_path = (tmp_path / "output.mp4").resolve()

    _assert_local_ffmpeg_paths(
        [(str(input_path), [])], [(str(output_path), [])], allowed_root=tmp_path
    )

    with pytest.raises(PolicyError):
        _assert_local_ffmpeg_paths(
            [("relative.mp4", [])], [(str(output_path), [])], allowed_root=tmp_path
        )

    outside = tmp_path.parent / "outside.mp4"
    with pytest.raises(PolicyError) as caught:
        _assert_local_ffmpeg_paths(
            [(str(input_path), [])], [(str(outside), [])], allowed_root=tmp_path
        )
    assert caught.value.code == "FFMPEG_OUTPUT_ROOT_DENIED"

    forbidden_arguments = (
        "Referer: https://cdn.invalid/?Signature=secret",
        "https%3A%2F%2Fcdn.invalid%2Fvideo%3FSignature%3Dsecret",
        r"https:\/\/cdn.invalid/video?Signature=secret",
        "Signature=secret",
    )
    for forbidden in forbidden_arguments:
        with pytest.raises(PolicyError) as caught:
            _assert_local_ffmpeg_paths(
                [(str(input_path), ["-headers", forbidden])],
                [(str(output_path), [])],
                allowed_root=tmp_path,
            )
        assert caught.value.code == "FFMPEG_REMOTE_INPUT_DENIED"
        assert "secret" not in str(caught.value)
