"""Stable application errors and process exit codes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class ExitCode(IntEnum):
    SUCCESS = 0
    USAGE = 2
    AUTHENTICATION = 3
    POLICY = 4
    REMOTE = 5
    PARTIAL = 6
    LOCAL_IO = 7
    BUSY = 8
    INTERNAL = 9
    INTERRUPTED = 130


@dataclass(slots=True)
class AppError(Exception):
    code: str
    message: str
    exit_code: ExitCode
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message


class UsageError(AppError):
    def __init__(self, message: str, *, code: str = "INVALID_INPUT", **details: Any) -> None:
        super().__init__(code, message, ExitCode.USAGE, False, details)


class AuthenticationError(AppError):
    def __init__(
        self,
        message: str = "Interactive authentication is required",
        *,
        code: str = "AUTH_REQUIRED",
        **details: Any,
    ) -> None:
        super().__init__(code, message, ExitCode.AUTHENTICATION, True, details)


class PolicyError(AppError):
    def __init__(self, message: str, *, code: str = "POLICY_DENIED", **details: Any) -> None:
        super().__init__(code, message, ExitCode.POLICY, False, details)


class RemoteError(AppError):
    def __init__(
        self,
        message: str,
        *,
        code: str = "DOWNLOAD_FAILED",
        retryable: bool = True,
        **details: Any,
    ) -> None:
        super().__init__(code, message, ExitCode.REMOTE, retryable, details)


class PartialFailure(AppError):
    def __init__(self, message: str, **details: Any) -> None:
        super().__init__("PARTIAL_SUCCESS", message, ExitCode.PARTIAL, True, details)


class LocalIOError(AppError):
    def __init__(
        self,
        message: str,
        *,
        code: str = "LOCAL_IO_ERROR",
        retryable: bool = False,
        **details: Any,
    ) -> None:
        super().__init__(code, message, ExitCode.LOCAL_IO, retryable, details)


class BusyError(AppError):
    def __init__(self, message: str = "Another mutating command is already running") -> None:
        super().__init__("BUSY", message, ExitCode.BUSY, True, {})
