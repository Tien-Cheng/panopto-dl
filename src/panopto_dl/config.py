"""Named profile configuration, safe application paths, and mutation locking."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import tomllib
from collections.abc import Iterator
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self
from urllib.parse import SplitResult, urlsplit, urlunsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import tomlkit
from filelock import FileLock, Timeout
from platformdirs import PlatformDirs
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from panopto_dl.domain import MediaPolicy
from panopto_dl.errors import BusyError

APP_NAME = "panopto-dl"
CONFIG_SCHEMA_VERSION = 1
NUS_SITE_URL = "https://mediaweb.ap.panopto.com"
PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
GIB = 1024**3


class ConfigError(ValueError):
    """The configuration is missing, malformed, or unsafe."""


class ProfileNotFoundError(ConfigError):
    pass


class ProfileAlreadyExistsError(ConfigError):
    pass


def validate_profile_name(name: str) -> str:
    """Validate a profile name before using it as a path segment or TOML key."""

    if not PROFILE_NAME_PATTERN.fullmatch(name):
        raise ConfigError(
            "profile names must start with an alphanumeric character and contain only "
            "letters, numbers, underscores, or hyphens"
        )
    return name


def _normalise_site_url(value: str) -> str:
    value = value.strip()
    parts = urlsplit(value)
    if parts.scheme.lower() != "https":
        raise ValueError("site_url must use HTTPS")
    if not parts.hostname or parts.username or parts.password:
        raise ValueError("site_url must contain a host and no user information")
    if parts.query or parts.fragment:
        raise ValueError("site_url must not contain a query string or fragment")
    if ".." in Path(parts.path).parts:
        raise ValueError("site_url path must not contain parent traversal")
    hostname = parts.hostname.encode("idna").decode("ascii").lower()
    if not hostname.endswith((".panopto.com", ".panopto.eu")):
        raise ValueError("site_url must name a Panopto-hosted site")
    if parts.port not in {None, 443}:
        raise ValueError("site_url must use the default HTTPS port")
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    path = parts.path.rstrip("/")
    if path not in {"", "/Panopto"}:
        raise ValueError("site_url must be a Panopto origin")
    canonical = SplitResult("https", netloc, path, "", "")
    return urlunsplit(canonical)


def _absolute_path(value: Path | str | os.PathLike[str]) -> Path:
    return Path(value).expanduser().resolve(strict=False)


class ResourceLimits(BaseModel):
    """Per-profile safeguards for unattended operations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_media_jobs: int = Field(default=2, ge=1, le=16)
    max_metadata_requests: int = Field(default=4, ge=1, le=64)
    fragment_concurrency: int = Field(default=1, ge=1, le=16)
    free_space_reserve_bytes: int = Field(default=20 * GIB, ge=0)
    max_sessions_per_run: int = Field(default=20, ge=1)
    max_estimated_bytes_per_run: int = Field(default=50 * GIB, ge=1)


class ProfileConfig(BaseModel):
    """Configuration for one Panopto account/site boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    site_url: str
    timezone: str = "UTC"
    output_root: Path
    browser_channel: str | None = None
    browser_executable: Path | None = None
    media_policy: MediaPolicy = MediaPolicy.LECTURE
    limits: ResourceLimits = Field(default_factory=ResourceLimits)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return validate_profile_name(value)

    @field_validator("site_url")
    @classmethod
    def validate_site_url(cls, value: str) -> str:
        return _normalise_site_url(value)

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"unknown IANA timezone: {value}") from exc
        return value

    @field_validator("output_root", "browser_executable", mode="before")
    @classmethod
    def normalise_paths(cls, value: object) -> object:
        if value is None:
            return None
        if not isinstance(value, (str, os.PathLike)):
            raise ValueError("filesystem paths must be strings or path-like values")
        return _absolute_path(value)

    @field_validator("browser_executable")
    @classmethod
    def executable_must_be_file_if_present(cls, value: Path | None) -> Path | None:
        if value is not None and value.exists() and not value.is_file():
            raise ValueError("browser_executable must point to a file")
        return value

    @field_validator("output_root")
    @classmethod
    def output_root_must_not_be_filesystem_root(cls, value: Path) -> Path:
        if value == Path(value.anchor):
            raise ValueError("output_root must not be a filesystem root")
        return value

    def fingerprint(self) -> str:
        """Return a stable hash used to bind an approved plan to this profile."""

        payload = self.model_dump(mode="json")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def resolve_output_path(self, *parts: str | os.PathLike[str]) -> Path:
        """Resolve an output path and reject absolute or traversal components."""

        if not parts:
            raise ConfigError("an output path must contain at least one component")
        relative = Path(*parts)
        if relative.is_absolute():
            raise ConfigError("output path must be relative to the configured output root")
        root = self.output_root.resolve(strict=False)
        candidate = (root / relative).resolve(strict=False)
        if candidate == root or not candidate.is_relative_to(root):
            raise ConfigError("output path escapes the configured output root")
        return candidate


class AppConfig(BaseModel):
    """The complete contents of the single application TOML file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = CONFIG_SCHEMA_VERSION
    default_profile: str | None = None
    profiles: dict[str, ProfileConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_profile_map(self) -> Self:
        if self.schema_version != CONFIG_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported configuration schema version {self.schema_version}; "
                f"expected {CONFIG_SCHEMA_VERSION}"
            )
        for key, profile in self.profiles.items():
            validate_profile_name(key)
            if key != profile.name:
                raise ValueError(
                    f"profile key {key!r} does not match profile name {profile.name!r}"
                )
        if self.default_profile is not None:
            validate_profile_name(self.default_profile)
            if self.default_profile not in self.profiles:
                raise ValueError("default_profile must name a configured profile")
        return self


@dataclass(frozen=True, slots=True)
class ProfilePaths:
    """Application-owned state paths for one named profile."""

    root: Path

    @property
    def database(self) -> Path:
        return self.root / "state.sqlite3"

    @property
    def browser(self) -> Path:
        return self.root / "browser"

    @property
    def mutation_lock(self) -> Path:
        return self.root / "mutation.lock"

    def ensure(self) -> None:
        _make_private_directory(self.root)
        _make_private_directory(self.browser)

    def lock(self) -> ProfileLock:
        return ProfileLock(self.mutation_lock)


@dataclass(frozen=True, slots=True)
class AppPaths:
    config_dir: Path
    data_dir: Path
    cache_dir: Path

    @classmethod
    def discover(cls) -> AppPaths:
        dirs = PlatformDirs(APP_NAME, appauthor=False, roaming=False)
        return cls(
            config_dir=Path(dirs.user_config_dir),
            data_dir=Path(dirs.user_data_dir),
            cache_dir=Path(dirs.user_cache_dir),
        )

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    def profile(self, name: str) -> ProfilePaths:
        safe_name = validate_profile_name(name)
        root = (self.data_dir / "profiles" / safe_name).resolve(strict=False)
        profiles_root = (self.data_dir / "profiles").resolve(strict=False)
        if not root.is_relative_to(profiles_root):
            raise ConfigError("profile state path escapes the application data directory")
        return ProfilePaths(root=root)

    def ensure(self) -> None:
        _make_private_directory(self.config_dir)
        _make_private_directory(self.data_dir)
        _make_private_directory(self.cache_dir)


def _make_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ConfigError("application state directory is unsafe")
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not path.is_dir():
            raise ConfigError("application state path is not a directory")
        path.chmod(0o700)
        if os.name != "nt":
            details = path.stat()
            if hasattr(os, "getuid") and details.st_uid != os.getuid():
                raise ConfigError("application state directory has an unsafe owner")
            if stat.S_IMODE(details.st_mode) & 0o077:
                raise ConfigError("application state directory permissions are unsafe")
    except OSError as exc:
        raise ConfigError("application state directory could not be secured") from exc


class ProfileLock(AbstractContextManager["ProfileLock"]):
    """A nonblocking OS-level mutation lock scoped to one profile."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = FileLock(path, timeout=0, mode=0o600, blocking=False)
        self._held = False

    def acquire(self) -> ProfileLock:
        if self._held:
            return self
        _make_private_directory(self.path.parent)
        try:
            self._lock.acquire(timeout=0)
        except Timeout as exc:
            raise BusyError() from exc
        self._held = True
        return self

    def release(self) -> None:
        if self._held:
            self._lock.release()
            self._held = False

    def __enter__(self) -> ProfileLock:
        return self.acquire()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()


class ConfigManager:
    """Load and atomically update named profiles in the application TOML file."""

    def __init__(self, paths: AppPaths | None = None, config_file: Path | None = None) -> None:
        self.paths = paths or AppPaths.discover()
        self.config_file = config_file or self.paths.config_file

    def load(self) -> AppConfig:
        if not self.config_file.exists():
            return AppConfig()
        try:
            with self.config_file.open("rb") as stream:
                raw = tomllib.load(stream)
            return AppConfig.model_validate(raw)
        except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
            raise ConfigError("configuration file is invalid or unreadable") from exc

    def save(self, config: AppConfig) -> None:
        validated = AppConfig.model_validate(config)
        self.paths.ensure()
        _make_private_directory(self.config_file.parent)
        document = _to_toml(validated)
        _atomic_write(self.config_file, tomlkit.dumps(document))

    def list_profiles(self) -> tuple[ProfileConfig, ...]:
        config = self.load()
        return tuple(config.profiles[name] for name in sorted(config.profiles))

    def get_profile(self, name: str | None = None) -> ProfileConfig:
        config = self.load()
        selected = name or config.default_profile
        if selected is None:
            raise ProfileNotFoundError("no profile selected and no default profile is configured")
        validate_profile_name(selected)
        try:
            return config.profiles[selected]
        except KeyError as exc:
            raise ProfileNotFoundError(f"profile {selected!r} is not configured") from exc

    def init_profile(
        self,
        name: str,
        *,
        output_root: Path,
        preset: str | None = None,
        site_url: str | None = None,
        timezone: str | None = None,
        browser_channel: str | None = None,
        browser_executable: Path | None = None,
        make_default: bool | None = None,
    ) -> ProfileConfig:
        """Create a profile without replacing existing configuration."""

        validate_profile_name(name)
        config = self.load()
        if name in config.profiles:
            raise ProfileAlreadyExistsError(f"profile {name!r} already exists")
        if preset not in {None, "nus"}:
            raise ConfigError(f"unknown profile preset: {preset}")
        resolved_site = site_url or (NUS_SITE_URL if preset == "nus" else None)
        if resolved_site is None:
            raise ConfigError("site_url is required when no preset supplies one")
        resolved_timezone = timezone or ("Asia/Singapore" if preset == "nus" else "UTC")
        if preset == "nus" and browser_channel is None and browser_executable is None:
            browser_channel = "chrome"
        profile = ProfileConfig(
            name=name,
            site_url=resolved_site,
            timezone=resolved_timezone,
            output_root=output_root,
            browser_channel=browser_channel,
            browser_executable=browser_executable,
        )
        profile_paths = self.paths.profile(name)
        profile_paths.ensure()
        output_existed = profile.output_root.exists()
        profile.output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not output_existed:
            profile.output_root.chmod(0o700)
        profiles = dict(config.profiles)
        profiles[name] = profile
        should_make_default = (
            make_default if make_default is not None else len(config.profiles) == 0
        )
        default_profile = name if should_make_default else config.default_profile
        updated = AppConfig(
            schema_version=CONFIG_SCHEMA_VERSION,
            default_profile=default_profile,
            profiles=profiles,
        )
        self.save(updated)
        return profile


def _to_toml(config: AppConfig) -> tomlkit.TOMLDocument:
    document = tomlkit.document()
    document.add("schema_version", config.schema_version)
    if config.default_profile is not None:
        document.add("default_profile", config.default_profile)
    profile_table = tomlkit.table()
    for name in sorted(config.profiles):
        profile = config.profiles[name]
        entry = tomlkit.table()
        entry.add("name", profile.name)
        entry.add("site_url", profile.site_url)
        entry.add("timezone", profile.timezone)
        entry.add("output_root", str(profile.output_root))
        if profile.browser_channel is not None:
            entry.add("browser_channel", profile.browser_channel)
        if profile.browser_executable is not None:
            entry.add("browser_executable", str(profile.browser_executable))
        entry.add("media_policy", profile.media_policy.value)
        limits = tomlkit.table()
        for key, value in profile.limits.model_dump(mode="python").items():
            limits.add(key, value)
        entry.add("limits", limits)
        profile_table.add(name, entry)
    document.add("profiles", profile_table)
    return document


def _atomic_write(path: Path, contents: str) -> None:
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        path.chmod(0o600)
    except OSError as exc:
        raise ConfigError("configuration file could not be written") from exc
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def iter_profile_names(config: AppConfig) -> Iterator[str]:
    """Yield profile names deterministically for human and JSON output."""

    yield from sorted(config.profiles)


__all__ = [
    "APP_NAME",
    "CONFIG_SCHEMA_VERSION",
    "NUS_SITE_URL",
    "AppConfig",
    "AppPaths",
    "ConfigError",
    "ConfigManager",
    "ProfileAlreadyExistsError",
    "ProfileConfig",
    "ProfileLock",
    "ProfileNotFoundError",
    "ProfilePaths",
    "ResourceLimits",
    "iter_profile_names",
    "validate_profile_name",
]
