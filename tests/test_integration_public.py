"""Opt-in smoke tests based on the public Panopto extractor fixtures.

Public demo recordings can disappear or change without notice, so these tests
are never part of the default unit run. The client receives an empty cookie file
and cannot depend on a local authenticated browser profile.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest

from panopto_dl.panopto import PanoptoClient
from panopto_dl.security import normalize_panopto_site

pytestmark = pytest.mark.integration

_ENABLE_ENV = "PANOPTO_DL_RUN_INTEGRATION"
_URL_ENV = "PANOPTO_DL_PUBLIC_TEST_URL"
_DEFAULT_VIEWER_URL = (
    "https://demo.hosted.panopto.com/Panopto/Pages/Viewer.aspx?"
    "id=26b3ae9e-4a48-4dcc-96ba-0befba08a0fb"
)
_CAPTION_URL = (
    "https://na-training-1.hosted.panopto.com/Panopto/Pages/Viewer.aspx?"
    "id=940cbd41-f616-4a45-b13e-aaf1000c915b"
)
_SLIDES_URL = (
    "https://demo.hosted.panopto.com/Panopto/Pages/Viewer.aspx?"
    "id=a7f12f1d-3872-4310-84b0-f8d8ab15326b"
)
_FOLDER_ID = "e4c6a2fc-1214-4ca0-8fb7-aef2e29ff63a"
_PRODUCT_FOLDER_ID = "bb0b58ff-b31b-47a0-9aa2-af6f0113613a"
_VIEWER_PATHS = {
    "/Panopto/Pages/Viewer.aspx",
    "/Panopto/Pages/Embed.aspx",
}


def _public_viewer_url() -> str:
    if os.environ.get(_ENABLE_ENV) != "1":
        pytest.skip(f"set {_ENABLE_ENV}=1 to enable public network tests")
    value = os.environ.get(_URL_ENV, _DEFAULT_VIEWER_URL)

    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in _VIEWER_PATHS
        or parsed.fragment
    ):
        pytest.fail(f"{_URL_ENV} must be a stable HTTPS Panopto Viewer or Embed URL")

    query = parse_qs(parsed.query, strict_parsing=True)
    if set(query) != {"id"} or len(query["id"]) != 1:
        pytest.fail(f"{_URL_ENV} must contain only one stable session id parameter")
    try:
        UUID(query["id"][0])
    except ValueError:
        pytest.fail(f"{_URL_ENV} contains an invalid session UUID")
    return value


def _empty_cookie_file(path: Path) -> Path:
    path.write_text("# Netscape HTTP Cookie File\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _client_for(url: str, tmp_path: Path) -> PanoptoClient:
    parsed = urlsplit(url)
    site_url = normalize_panopto_site(f"{parsed.scheme}://{parsed.netloc}")
    return PanoptoClient(
        site_url,
        _empty_cookie_file(tmp_path / "public.cookies.txt"),
        tmp_path / "downloads",
    )


def test_public_viewer_metadata_contract(tmp_path: Path) -> None:
    viewer_url = _public_viewer_url()
    parsed = urlsplit(viewer_url)
    site_url = normalize_panopto_site(f"{parsed.scheme}://{parsed.netloc}")
    client = _client_for(viewer_url, tmp_path)

    session = client.inspect(viewer_url)

    UUID(session.session_id)
    assert session.title.strip()
    returned_url = urlsplit(session.url)
    assert f"{returned_url.scheme}://{returned_url.netloc}" == site_url
    assert returned_url.path == "/Panopto/Pages/Viewer.aspx"
    assert set(parse_qs(returned_url.query)) == {"id"}

    public_payload = json.dumps(session.as_dict(), default=str).lower()
    for secret_marker in ("signature=", "token=", "cookie", "authorization"):
        assert secret_marker not in public_payload


def test_public_folder_enumeration_and_deduplication(tmp_path: Path) -> None:
    _public_viewer_url()
    client = _client_for(_DEFAULT_VIEWER_URL, tmp_path)

    folders = client.discover_folders(_FOLDER_ID, recursive=False)
    folder_identifiers = [folder.folder_id for folder in folders]
    assert folders
    assert len(folder_identifiers) == len(set(folder_identifiers))

    sessions = client.discover_sessions(_PRODUCT_FOLDER_ID, recursive=False)
    assert sessions
    identifiers = [session.session_id for session in sessions]
    assert len(identifiers) == len(set(identifiers))


def test_public_root_listing_paginates(tmp_path: Path) -> None:
    _public_viewer_url()
    client = _client_for(_DEFAULT_VIEWER_URL, tmp_path)

    sessions = client.discover_sessions(
        "https://demo.hosted.panopto.com/Panopto/Pages/Sessions/List.aspx",
        recursive=False,
        max_sessions=1_000,
    )

    identifiers = [session.session_id for session in sessions]
    assert len(identifiers) > 250
    assert len(identifiers) == len(set(identifiers))


def test_public_captions_and_stream_summaries(tmp_path: Path) -> None:
    _public_viewer_url()
    session = _client_for(_CAPTION_URL, tmp_path).inspect(_CAPTION_URL)

    assert session.formats
    assert session.subtitles
    assert all(summary.language for summary in session.subtitles)


def test_public_timed_slide_presentation(tmp_path: Path) -> None:
    _public_viewer_url()
    session = _client_for(_SLIDES_URL, tmp_path).inspect(_SLIDES_URL)

    assert any(summary.extension == "mhtml" for summary in session.formats)
    assert session.chapters
