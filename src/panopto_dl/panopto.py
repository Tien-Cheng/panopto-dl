"""Sanitizing embedded yt-dlp adapter for Panopto discovery and downloads."""

from __future__ import annotations

import json
import os
import re
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, cast
from urllib.parse import parse_qs, urlsplit

from .domain import MediaPolicy, SessionState
from .errors import (
    AppError,
    AuthenticationError,
    LocalIOError,
    PolicyError,
    RemoteError,
    UsageError,
)
from .filesystem import ensure_no_symlink_components, ensure_within_root
from .security import (
    Redactor,
    canonical_uuid,
    ensure_private_file,
    folder_url,
    normalize_panopto_site,
    redact_text,
    validate_allowed_url,
    viewer_url,
)

_SESSION_PAGE_RE: Final[re.Pattern[str]] = re.compile(
    r"/Panopto/Pages/(?:Viewer|Embed)\.aspx$", re.IGNORECASE
)
_FOLDER_PAGE_RE: Final[re.Pattern[str]] = re.compile(
    r"/Panopto/Pages/Sessions/List\.aspx$", re.IGNORECASE
)
_SAFE_FORMAT_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.-]+$")
_REMOTE_MEDIA_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9+.-]*://|data:|crypto:|pipe:)", re.IGNORECASE
)
_REMOTE_REFERENCE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:[A-Za-z][A-Za-z0-9+.-]*://|data:|crypto:|pipe:)", re.IGNORECASE
)
_FFMPEG_FORBIDDEN_ARGUMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:[A-Za-z][A-Za-z0-9+.-]*://|https?%3a%2f%2f|https?:\\/\\/|"
    r"https?:\\u002f\\u002f|\b(?:signature|sig|token|policy|key-pair-id|"
    r"x-amz-(?:credential|signature|security-token))\s*=|"
    r"\b(?:authorization|cookie|set-cookie)\s*:|\b(?:bearer|basic)\s+)",
    re.IGNORECASE,
)
_OUTPUT_ROOT_OPTION: Final[str] = "_panopto_dl_output_root"


@dataclass(frozen=True, slots=True)
class FormatSummary:
    format_id: str
    extension: str | None
    protocol: str | None
    video_codec: str | None
    audio_codec: str | None
    width: int | None
    height: int | None
    fps: float | None
    bitrate_kbps: float | None
    size_bytes: int | None
    note: str | None


@dataclass(frozen=True, slots=True)
class SubtitleSummary:
    language: str
    extensions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ChapterSummary:
    title: str
    start_seconds: float
    end_seconds: float | None


@dataclass(frozen=True, slots=True)
class PanoptoFolder:
    folder_id: str
    name: str
    url: str
    parent_id: str | None = None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PanoptoSession:
    session_id: str
    title: str
    url: str
    folder_id: str | None
    folder_name: str | None
    recorded_at: datetime | None
    duration_seconds: float | None
    uploader: str | None
    description: str | None
    state: SessionState
    estimated_bytes: int | None
    formats: tuple[FormatSummary, ...]
    subtitles: tuple[SubtitleSummary, ...]
    chapters: tuple[ChapterSummary, ...]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    status: str
    filename: str | None
    downloaded_bytes: int | None
    total_bytes: int | None
    speed_bytes_per_second: float | None
    eta_seconds: float | None
    fragment_index: int | None
    fragment_count: int | None


@dataclass(frozen=True, slots=True)
class DownloadResult:
    session: PanoptoSession
    media_policy: MediaPolicy
    state: SessionState
    destination: Path
    artifacts: tuple[Path, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "session": self.session.as_dict(),
            "media_policy": self.media_policy.value,
            "state": self.state.value,
            "destination": str(self.destination),
            "artifacts": [str(path) for path in self.artifacts],
        }


class _YtDlpLogger:
    def __init__(
        self,
        redactor: Redactor,
        sink: Callable[[str, str], None] | None,
    ) -> None:
        self._redactor = redactor
        self._sink = sink

    def debug(self, message: object) -> None:
        self._emit("debug", message)

    def info(self, message: object) -> None:
        self._emit("info", message)

    def warning(self, message: object) -> None:
        self._emit("warning", message)

    def error(self, message: object) -> None:
        self._emit("error", message)

    def _emit(self, level: str, message: object) -> None:
        if self._sink is not None:
            self._sink(level, self._redactor.text(message))


class PanoptoClient:
    """Embed yt-dlp while keeping transport secrets inside this object.

    ``cookie_file`` is expected to come from ``BrowserSession.cookies_file``.
    The caller must keep that context manager open for the lifetime of this
    client operation.
    """

    def __init__(
        self,
        base_url: str,
        cookie_file: Path,
        output_root: Path,
        quiet: bool = True,
        *,
        ydl_factory: Callable[[Mapping[str, Any]], Any] | None = None,
        log_hook: Callable[[str, str], None] | None = None,
    ) -> None:
        self.base_url = normalize_panopto_site(base_url)
        self.cookie_file = ensure_private_file(cookie_file.expanduser())
        self.output_root = output_root.expanduser().resolve()
        self.quiet = quiet
        self._ydl_factory = ydl_factory or _default_ydl_factory
        self._redactor = Redactor((self.cookie_file,))
        self._logger = _YtDlpLogger(self._redactor, log_hook)

    def inspect(self, url_or_id: str) -> PanoptoSession:
        """Extract one recording and return metadata with all URLs removed."""

        url = self._session_url(url_or_id)
        raw = self._extract(
            url,
            download=False,
            options={
                "noplaylist": True,
                "writesubtitles": True,
                "writeautomaticsub": False,
                "subtitleslangs": ["all"],
                "subtitlesformat": "srt/best",
            },
        )
        return self._session_from_info(raw, fallback_id=self._session_id(url))

    def discover_folders(
        self,
        url: str | None = None,
        *,
        recursive: bool = True,
        max_folders: int = 1_000,
    ) -> list[PanoptoFolder]:
        """Enumerate accessible child folders, optionally walking descendants."""

        if max_folders <= 0:
            raise UsageError("Maximum folder count must be positive")
        start_url, start_id = self._folder_url_and_id(url)
        queue: deque[tuple[str, str | None]] = deque([(start_url, start_id)])
        visited: set[str] = set()
        folders: dict[str, PanoptoFolder] = {}

        while queue:
            current_url, parent_id = queue.popleft()
            visit_key = parent_id or current_url
            if visit_key in visited:
                continue
            visited.add(visit_key)
            playlist = self._extract_flat_playlist(current_url)
            for entry in _entries(playlist):
                if not _is_folder_entry(entry):
                    continue
                identifier = _safe_uuid(entry.get("id"))
                if identifier is None or identifier in folders:
                    continue
                item = PanoptoFolder(
                    folder_id=identifier,
                    name=_safe_text(entry.get("title"), fallback="Untitled folder"),
                    url=folder_url(self.base_url, identifier),
                    parent_id=parent_id,
                )
                folders[identifier] = item
                if len(folders) > max_folders:
                    raise RemoteError(
                        "Panopto folder discovery exceeded the configured limit",
                        code="DISCOVERY_LIMIT",
                        retryable=False,
                    )
                if recursive:
                    queue.append((item.url, item.folder_id))
        return list(folders.values())

    def discover_sessions(
        self,
        folder_url_or_id: str,
        *,
        recursive: bool = True,
        hydrate: bool = False,
        max_sessions: int = 10_000,
    ) -> list[PanoptoSession]:
        """Enumerate recordings in a folder using yt-dlp's paged list extractor."""

        if max_sessions <= 0:
            raise UsageError("Maximum session count must be positive")
        start_url, start_id = self._folder_url_and_id(folder_url_or_id)
        queue: deque[tuple[str, str | None]] = deque([(start_url, start_id)])
        visited_folders: set[str] = set()
        sessions: dict[str, PanoptoSession] = {}

        while queue:
            current_url, current_folder_id = queue.popleft()
            visit_key = current_folder_id or current_url
            if visit_key in visited_folders:
                continue
            visited_folders.add(visit_key)
            playlist = self._extract_flat_playlist(current_url)
            for entry in _entries(playlist):
                if _is_folder_entry(entry):
                    if recursive:
                        child_id = _safe_uuid(entry.get("id"))
                        if child_id is not None:
                            queue.append((folder_url(self.base_url, child_id), child_id))
                    continue

                identifier = _safe_uuid(entry.get("id"))
                if identifier is None or identifier in sessions:
                    continue
                if hydrate:
                    session = self.inspect(identifier)
                else:
                    session = self._session_from_flat_entry(entry, current_folder_id)
                sessions[identifier] = session
                if len(sessions) > max_sessions:
                    raise RemoteError(
                        "Panopto session discovery exceeded the configured limit",
                        code="DISCOVERY_LIMIT",
                        retryable=False,
                    )
        return list(sessions.values())

    def download(
        self,
        session_or_url: PanoptoSession | str,
        destination_dir: Path,
        media_profile: MediaPolicy | str = MediaPolicy.LECTURE,
        progress_hook: Callable[[ProgressEvent], None] | None = None,
    ) -> DownloadResult:
        """Download one session with native network transports and safe hooks."""

        policy = _media_policy(media_profile)
        session_ref = (
            session_or_url.session_id
            if isinstance(session_or_url, PanoptoSession)
            else session_or_url
        )
        url = self._session_url(session_ref)
        destination = self._prepare_destination(destination_dir)

        raw = self._extract(url, download=False, options={"noplaylist": True})
        session = self._session_from_info(raw, fallback_id=self._session_id(url))
        if session.state == SessionState.NOT_READY:
            raise RemoteError(
                "The Panopto recording is not ready to download",
                code="NOT_READY",
                retryable=True,
            )

        format_selector, composite = _format_selector(raw, policy)
        output_template = _output_template(destination, policy, composite)
        options: dict[str, Any] = {
            "noplaylist": True,
            "skip_download": False,
            "format": format_selector,
            "format_sort": ["res:1080", "vcodec:h264", "acodec:aac", "ext:mp4:m4a"],
            "format_sort_force": True,
            "merge_output_format": "mp4" if policy == MediaPolicy.LECTURE else None,
            "outtmpl": output_template,
            "writesubtitles": True,
            "writeautomaticsub": False,
            "subtitleslangs": ["all"],
            "subtitlesformat": "srt/best",
            "progress_hooks": [self._safe_progress_hook(progress_hook)],
            "continuedl": True,
            "nopart": False,
            "overwrites": False,
            "trim_file_name": 180,
        }
        if policy is MediaPolicy.LECTURE and not composite:
            options["postprocessors"] = [{"key": "FFmpegVideoRemuxer", "preferedformat": "mp4"}]
        self._extract(url, download=True, options=options)
        if composite:
            _normalize_composite_names(destination)
        elif policy == MediaPolicy.ALL_STREAMS:
            _normalize_slide_name(destination)

        artifacts_before_metadata = tuple(_artifact_paths(destination))
        final_state = SessionState.NEEDS_COMPOSITE if composite else SessionState.COMPLETE
        metadata_path = destination / "metadata.json"
        self._write_metadata(metadata_path, session, policy, final_state, artifacts_before_metadata)
        artifacts = tuple(_artifact_paths(destination))
        return DownloadResult(session, policy, final_state, destination, artifacts)

    def _extract_flat_playlist(self, url: str) -> Mapping[str, Any]:
        raw = self._extract(
            url,
            download=False,
            options={"extract_flat": "in_playlist", "lazy_playlist": False},
        )
        if not isinstance(raw, Mapping) or raw.get("_type") != "playlist":
            raise RemoteError(
                "Panopto did not return a folder listing",
                code="DISCOVERY_FAILED",
                retryable=True,
            )
        return raw

    def _extract(
        self,
        url: str,
        *,
        download: bool,
        options: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        validate_allowed_url(url, self.base_url)
        ensure_private_file(self.cookie_file)
        params = self._base_ydl_options()
        params.update(options)
        try:
            with self._ydl_factory(params) as ydl:
                result = ydl.extract_info(url, download=download)
        except KeyboardInterrupt:
            raise
        except AppError:
            raise
        except Exception as exc:
            translated = _translate_yt_dlp_error(exc, self._redactor)
            raise translated from None
        if not isinstance(result, Mapping):
            raise RemoteError(
                "Panopto returned no usable recording information",
                code="EXTRACTION_FAILED",
                retryable=True,
            )
        return result

    def _base_ydl_options(self) -> dict[str, Any]:
        return {
            _OUTPUT_ROOT_OPTION: str(self.output_root),
            "cookiefile": str(self.cookie_file),
            "quiet": True,
            "noprogress": True,
            "no_warnings": True,
            "logger": self._logger,
            "skip_download": True,
            "mark_watched": False,
            "cachedir": False,
            "geo_bypass": False,
            "remote_components": [],
            "allowed_extractors": ["Panopto", "PanoptoList", "PanoptoPlaylist"],
            # Network streams must use yt-dlp's native downloaders.  FFmpeg is
            # still available to merge already-downloaded local fragments.
            "external_downloader": {
                "default": "native",
                "http": "native",
                "m3u8": "native",
                "dash": "native",
            },
            "hls_prefer_native": True,
            "concurrent_fragment_downloads": 1,
            # AppService owns bounded whole-operation retries so it can refresh
            # authentication and write an auditable attempt for each one.
            "retries": 0,
            "fragment_retries": 3,
            "extractor_retries": 0,
        }

    def _session_from_flat_entry(
        self, entry: Mapping[str, Any], folder_id: str | None
    ) -> PanoptoSession:
        identifier = canonical_uuid(str(entry.get("id") or ""))
        return PanoptoSession(
            session_id=identifier,
            title=_safe_text(entry.get("title"), fallback="Untitled recording"),
            url=viewer_url(self.base_url, identifier),
            folder_id=_safe_uuid(entry.get("channel_id")) or folder_id,
            folder_name=_safe_optional_text(entry.get("channel")),
            recorded_at=_timestamp(entry.get("timestamp")),
            duration_seconds=_safe_float(entry.get("duration")),
            uploader=_safe_optional_text(entry.get("uploader")),
            description=_safe_optional_text(entry.get("description")),
            state=_session_state(entry),
            estimated_bytes=_estimated_size(entry.get("formats")),
            formats=(),
            subtitles=(),
            chapters=(),
        )

    def _session_from_info(self, info: Mapping[str, Any], *, fallback_id: str) -> PanoptoSession:
        identifier = _safe_uuid(info.get("id")) or canonical_uuid(fallback_id)
        formats = tuple(_format_summary(item) for item in _format_mappings(info.get("formats")))
        return PanoptoSession(
            session_id=identifier,
            title=_safe_text(info.get("title"), fallback="Untitled recording"),
            url=viewer_url(self.base_url, identifier),
            folder_id=_safe_uuid(info.get("channel_id")),
            folder_name=_safe_optional_text(info.get("channel")),
            recorded_at=_timestamp(info.get("timestamp")),
            duration_seconds=_safe_float(info.get("duration")),
            uploader=_safe_optional_text(info.get("uploader")),
            description=_safe_optional_text(info.get("description")),
            state=_session_state(info),
            estimated_bytes=_estimated_size(info.get("formats")),
            formats=formats,
            subtitles=_subtitle_summaries(info.get("subtitles")),
            chapters=_chapter_summaries(info.get("chapters")),
        )

    def _session_url(self, value: str) -> str:
        try:
            return viewer_url(self.base_url, value)
        except AppError:
            pass
        url = validate_allowed_url(value, self.base_url)
        parsed = urlsplit(url)
        if not _SESSION_PAGE_RE.fullmatch(parsed.path):
            raise UsageError("Expected a Panopto Viewer or Embed URL")
        query = parse_qs(parsed.query)
        values = query.get("id") or query.get("pid")
        if not values:
            raise UsageError("Panopto session URL has no recording identifier")
        return viewer_url(self.base_url, values[0])

    def _session_id(self, url: str) -> str:
        query = parse_qs(urlsplit(url).query)
        values = query.get("id") or query.get("pid")
        if not values:
            raise UsageError("Panopto session URL has no recording identifier")
        return canonical_uuid(values[0])

    def _folder_url_and_id(self, value: str | None) -> tuple[str, str | None]:
        if value is None:
            return folder_url(self.base_url), None
        try:
            identifier = canonical_uuid(value)
        except AppError:
            identifier = None
        if identifier is not None:
            return folder_url(self.base_url, identifier), identifier

        url = validate_allowed_url(value, self.base_url)
        parsed = urlsplit(url)
        if not _FOLDER_PAGE_RE.fullmatch(parsed.path):
            raise UsageError("Expected a Panopto folder URL")
        values = parse_qs(parsed.fragment).get("folderID")
        if not values:
            return folder_url(self.base_url), None
        identifier = canonical_uuid(values[0].strip('"'))
        return folder_url(self.base_url, identifier), identifier

    def _prepare_destination(self, destination: Path) -> Path:
        self.output_root.mkdir(parents=True, exist_ok=True)
        lexical_destination = ensure_no_symlink_components(destination, self.output_root)
        safe_destination = ensure_within_root(lexical_destination, self.output_root)
        safe_destination.mkdir(parents=True, exist_ok=True)
        safe_destination.chmod(0o700)
        ensure_no_symlink_components(safe_destination, self.output_root)
        for child in safe_destination.iterdir():
            if child.is_symlink() or not child.is_file():
                raise PolicyError(
                    "The resumable staging directory contains an unsafe entry",
                    code="OUTPUT_SYMLINK_DENIED",
                )
        return safe_destination

    @staticmethod
    def _safe_progress_hook(
        hook: Callable[[ProgressEvent], None] | None,
    ) -> Callable[[Mapping[str, Any]], None]:
        def emit(raw: Mapping[str, Any]) -> None:
            if hook is None:
                return
            raw_filename = raw.get("filename") or raw.get("tmpfilename")
            filename = _safe_optional_text(Path(str(raw_filename)).name) if raw_filename else None
            hook(
                ProgressEvent(
                    status=_safe_text(raw.get("status"), fallback="unknown"),
                    filename=filename,
                    downloaded_bytes=_safe_int(raw.get("downloaded_bytes")),
                    total_bytes=_safe_int(
                        raw.get("total_bytes") or raw.get("total_bytes_estimate")
                    ),
                    speed_bytes_per_second=_safe_float(raw.get("speed")),
                    eta_seconds=_safe_float(raw.get("eta")),
                    fragment_index=_safe_int(raw.get("fragment_index")),
                    fragment_count=_safe_int(raw.get("fragment_count")),
                )
            )

        return emit

    @staticmethod
    def _write_metadata(
        path: Path,
        session: PanoptoSession,
        policy: MediaPolicy,
        state: SessionState,
        artifacts: tuple[Path, ...],
    ) -> None:
        payload = {
            "schema_version": "1.0",
            "session": _json_safe_session(session),
            "media_policy": policy.value,
            "state": state.value,
            "artifacts": [item.name for item in artifacts],
        }
        temporary = path.with_suffix(path.suffix + ".part")
        try:
            if temporary.is_symlink() or (temporary.exists() and not temporary.is_file()):
                raise PolicyError(
                    "Recording metadata staging is unsafe",
                    code="OUTPUT_SYMLINK_DENIED",
                )
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary, flags, 0o600)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(
                    json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
                )
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
        except PolicyError:
            raise
        except OSError:
            raise LocalIOError("Safe recording metadata could not be written") from None


def _default_ydl_factory(options: Mapping[str, Any]) -> Any:
    from yt_dlp import YoutubeDL  # type: ignore[import-untyped]
    from yt_dlp.downloader import get_suitable_downloader  # type: ignore[import-untyped]
    from yt_dlp.downloader.external import FFmpegFD  # type: ignore[import-untyped]
    from yt_dlp.postprocessor.ffmpeg import (  # type: ignore[import-untyped]
        FFmpegPostProcessor,
    )

    safe_options = dict(options)
    raw_output_root = safe_options.pop(_OUTPUT_ROOT_OPTION, None)
    allowed_output_root = (
        Path(raw_output_root).expanduser().resolve()
        if isinstance(raw_output_root, str) and Path(raw_output_root).expanduser().is_absolute()
        else None
    )

    class SafeYoutubeDL(YoutubeDL):  # type: ignore[misc]
        """Prevent yt-dlp upgrades from turning FFmpeg into a network client."""

        def dl(
            self,
            name: str,
            info: Mapping[str, Any],
            subtitle: bool = False,
            test: bool = False,
        ) -> tuple[bool, bool]:
            downloader = get_suitable_downloader(info, self.params, to_stdout=name == "-")
            if downloader is FFmpegFD:
                raise PolicyError(
                    "Remote media may not be passed to FFmpeg",
                    code="FFMPEG_REMOTE_INPUT_DENIED",
                )
            return cast(
                tuple[bool, bool],
                super().dl(name, info, subtitle=subtitle, test=test),
            )

        def run_pp(self, pp: Any, infodict: dict[str, Any]) -> dict[str, Any]:
            if not isinstance(pp, FFmpegPostProcessor):
                return cast(dict[str, Any], super().run_pp(pp, infodict))

            original = pp.real_run_ffmpeg

            def guarded_ffmpeg(
                input_path_opts: Iterable[tuple[str, list[str]]],
                output_path_opts: Iterable[tuple[str, list[str]]],
                **kwargs: Any,
            ) -> Any:
                safe_inputs = list(input_path_opts)
                safe_outputs = list(output_path_opts)
                _assert_local_ffmpeg_paths(
                    safe_inputs,
                    safe_outputs,
                    allowed_root=allowed_output_root,
                )
                return original(safe_inputs, safe_outputs, **kwargs)

            pp.real_run_ffmpeg = guarded_ffmpeg
            try:
                return cast(dict[str, Any], super().run_pp(pp, infodict))
            finally:
                pp.real_run_ffmpeg = original

    return SafeYoutubeDL(safe_options)


def _assert_local_ffmpeg_paths(
    inputs: Iterable[tuple[str, list[str]]],
    outputs: Iterable[tuple[str, list[str]]],
    *,
    allowed_root: Path | None = None,
) -> None:
    input_items = tuple(inputs)
    output_items = tuple(outputs)
    for path, arguments in (*input_items, *output_items):
        if (
            not isinstance(path, str)
            or path == "-"
            or _REMOTE_MEDIA_RE.match(path)
            or not Path(path).expanduser().is_absolute()
            or any(
                not isinstance(argument, str)
                or _REMOTE_REFERENCE_RE.search(argument)
                or _FFMPEG_FORBIDDEN_ARGUMENT_RE.search(argument)
                for argument in arguments
            )
        ):
            raise PolicyError(
                "Remote media may not be passed to FFmpeg",
                code="FFMPEG_REMOTE_INPUT_DENIED",
            )
        resolved = Path(path).expanduser().resolve()
        if allowed_root is not None and not resolved.is_relative_to(allowed_root.resolve()):
            raise PolicyError(
                "FFmpeg paths must remain inside the configured output root",
                code="FFMPEG_OUTPUT_ROOT_DENIED",
            )
    if allowed_root is None:
        raise PolicyError(
            "FFmpeg output root validation is unavailable",
            code="FFMPEG_OUTPUT_ROOT_DENIED",
        )
    for path, _arguments in input_items:
        if not Path(path).is_file():
            raise PolicyError(
                "FFmpeg inputs must be downloaded local files",
                code="FFMPEG_REMOTE_INPUT_DENIED",
            )


def _translate_yt_dlp_error(exc: Exception, redactor: Redactor) -> AppError:
    safe_message = redactor.text(exc).lower()
    auth_tokens = (
        "login",
        "log in",
        "sign in",
        "cookie",
        "forbidden",
        "unauthorized",
        "http error 401",
        "http error 403",
    )
    if any(token in safe_message for token in auth_tokens):
        return AuthenticationError()
    if any(token in safe_message for token in ("processing", "not yet available", "is live")):
        return RemoteError(
            "The Panopto recording is not ready to download",
            code="NOT_READY",
            retryable=True,
        )
    unsupported_tokens = ("unsupported url", "no video formats", "private video")
    if any(token in safe_message for token in unsupported_tokens):
        return RemoteError(
            "Panopto did not expose a supported downloadable recording",
            code="UNSUPPORTED_RECORDING",
            retryable=False,
        )
    return RemoteError("Panopto extraction or download failed", retryable=True)


def _entries(playlist: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    raw_entries = playlist.get("entries")
    if raw_entries is None:
        return ()
    return (item for item in raw_entries if isinstance(item, Mapping))


def _is_folder_entry(entry: Mapping[str, Any]) -> bool:
    if str(entry.get("ie_key") or "").lower() == "panoptolist":
        return True
    value = entry.get("url")
    if not isinstance(value, str):
        return False
    try:
        return bool(_FOLDER_PAGE_RE.fullmatch(urlsplit(value).path))
    except ValueError:
        return False


def _format_mappings(value: object) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, Mapping)):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _format_summary(value: Mapping[str, Any]) -> FormatSummary:
    return FormatSummary(
        format_id=_safe_text(value.get("format_id"), fallback="unknown"),
        extension=_safe_optional_text(value.get("ext")),
        protocol=_safe_optional_text(value.get("protocol")),
        video_codec=_safe_optional_text(value.get("vcodec")),
        audio_codec=_safe_optional_text(value.get("acodec")),
        width=_safe_int(value.get("width")),
        height=_safe_int(value.get("height")),
        fps=_safe_float(value.get("fps")),
        bitrate_kbps=_safe_float(value.get("tbr")),
        size_bytes=_safe_int(value.get("filesize") or value.get("filesize_approx")),
        note=_safe_optional_text(value.get("format_note")),
    )


def _subtitle_summaries(value: object) -> tuple[SubtitleSummary, ...]:
    if not isinstance(value, Mapping):
        return ()
    summaries: list[SubtitleSummary] = []
    for raw_language, raw_tracks in value.items():
        language = _safe_text(raw_language, fallback="default")
        extensions: set[str] = set()
        if isinstance(raw_tracks, Iterable) and not isinstance(raw_tracks, (str, bytes, Mapping)):
            for track in raw_tracks:
                if isinstance(track, Mapping):
                    extension = _safe_optional_text(track.get("ext"))
                    if extension:
                        extensions.add(extension)
        summaries.append(SubtitleSummary(language, tuple(sorted(extensions))))
    return tuple(summaries)


def _chapter_summaries(value: object) -> tuple[ChapterSummary, ...]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, Mapping)):
        return ()
    chapters: list[ChapterSummary] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        start = _safe_float(item.get("start_time"))
        if start is None:
            continue
        chapters.append(
            ChapterSummary(
                _safe_text(item.get("title"), fallback="Chapter"),
                start,
                _safe_float(item.get("end_time")),
            )
        )
    return tuple(chapters)


def _session_state(info: Mapping[str, Any]) -> SessionState:
    live_status = str(info.get("live_status") or "").lower()
    availability = str(info.get("availability") or "").lower()
    if (
        info.get("is_live")
        or live_status
        in {
            "is_live",
            "is_upcoming",
            "post_live",
        }
        or availability in {"processing", "scheduled"}
    ):
        return SessionState.NOT_READY
    return SessionState.DISCOVERED


def _estimated_size(value: object) -> int | None:
    formats = _format_mappings(value)
    sizes = [
        size
        for item in formats
        if (size := _safe_int(item.get("filesize") or item.get("filesize_approx"))) is not None
    ]
    return max(sizes) if sizes else None


def _format_selector(info: Mapping[str, Any], policy: MediaPolicy) -> tuple[str, bool]:
    formats = _format_mappings(info.get("formats"))
    if policy == MediaPolicy.AUDIO:
        return "bestaudio/best", False
    if policy == MediaPolicy.ALL_STREAMS:
        return "all", False

    has_video = any(_has_video(item) for item in formats)
    audio_ids = [
        str(item.get("format_id"))
        for item in formats
        if _has_audio(item) and not _has_video(item) and _safe_format_id(item.get("format_id"))
    ]
    slide_ids = [
        str(item.get("format_id"))
        for item in formats
        if _is_slide_format(item) and _safe_format_id(item.get("format_id"))
    ]
    if not has_video and audio_ids and slide_ids:
        return f"{audio_ids[-1]},{slide_ids[0]}", True
    return (
        "b[format_note*=PODCAST][height<=1080]/"
        "bv*[height<=1080]+ba/b[height<=1080]/best[height<=1080]/best",
        False,
    )


def _output_template(destination: Path, policy: MediaPolicy, composite: bool) -> dict[str, str]:
    if policy == MediaPolicy.ALL_STREAMS:
        default = destination / "stream-%(format_id)s.%(ext)s"
    elif composite:
        default = destination / "asset-%(format_id)s.%(ext)s"
    elif policy == MediaPolicy.AUDIO:
        default = destination / "audio.%(ext)s"
    else:
        default = destination / "lecture.%(ext)s"
    return {
        "default": str(default),
        "subtitle": str(destination / "captions.%(language)s.%(ext)s"),
    }


def _normalize_composite_names(destination: Path) -> None:
    for path in tuple(destination.glob("asset-*")):
        if path.suffix.lower() == ".mhtml":
            target = destination / "slides.mhtml"
        else:
            target = destination / f"lecture{path.suffix.lower()}"
        if target.exists() or path.name.endswith((".part", ".ytdl")):
            continue
        path.replace(target)


def _normalize_slide_name(destination: Path) -> None:
    slides = sorted(destination.glob("stream-*.mhtml"))
    if len(slides) == 1 and not (destination / "slides.mhtml").exists():
        slides[0].replace(destination / "slides.mhtml")


def _artifact_paths(destination: Path) -> Iterable[Path]:
    for item in sorted(destination.iterdir()):
        if item.is_symlink():
            raise PolicyError(
                "Downloaded artifacts must not be symbolic links",
                code="OUTPUT_SYMLINK_DENIED",
            )
        if not item.is_file() or item.name.endswith((".part", ".ytdl")):
            continue
        yield item


def _media_policy(value: MediaPolicy | str) -> MediaPolicy:
    if isinstance(value, MediaPolicy):
        return value
    try:
        return MediaPolicy(value)
    except ValueError:
        raise UsageError("Unknown media profile") from None


def _has_video(value: Mapping[str, Any]) -> bool:
    codec = value.get("vcodec")
    return codec not in {None, "none"} and not _is_slide_format(value)


def _has_audio(value: Mapping[str, Any]) -> bool:
    return value.get("acodec") not in {None, "none"}


def _is_slide_format(value: Mapping[str, Any]) -> bool:
    return value.get("ext") == "mhtml" or value.get("protocol") == "mhtml"


def _safe_format_id(value: object) -> bool:
    return isinstance(value, str) and bool(_SAFE_FORMAT_ID_RE.fullmatch(value))


def _safe_uuid(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return canonical_uuid(value)
    except AppError:
        return None


def _safe_text(value: object, *, fallback: str) -> str:
    if value is None:
        return fallback
    sanitized = redact_text(value).strip()
    return sanitized or fallback


def _safe_optional_text(value: object) -> str | None:
    if value is None:
        return None
    sanitized = redact_text(value).strip()
    return sanitized or None


def _safe_int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if not isinstance(value, (str, bytes, bytearray, int, float)):
        return None
    try:
        converted = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return converted if converted >= 0 else None


def _safe_float(value: object) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if not isinstance(value, (str, bytes, bytearray, int, float)):
        return None
    try:
        converted = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return converted if converted >= 0 else None


def _timestamp(value: object) -> datetime | None:
    timestamp = _safe_float(value)
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _json_safe_session(session: PanoptoSession) -> dict[str, object]:
    payload = session.as_dict()
    recorded_at = payload.get("recorded_at")
    if isinstance(recorded_at, datetime):
        payload["recorded_at"] = recorded_at.isoformat().replace("+00:00", "Z")
    state = payload.get("state")
    if isinstance(state, SessionState):
        payload["state"] = state.value
    return payload


__all__ = [
    "ChapterSummary",
    "DownloadResult",
    "FormatSummary",
    "PanoptoClient",
    "PanoptoFolder",
    "PanoptoSession",
    "ProgressEvent",
    "SubtitleSummary",
]
