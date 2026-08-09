"""Human and machine output with a stable JSON envelope."""

from __future__ import annotations

import json
import sys
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from rich.console import Console

from .errors import AppError, ExitCode


class ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    retryable: bool
    details: dict[str, Any] = Field(default_factory=dict)


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    command: str
    status: Literal["success", "partial", "error"]
    profile: str
    request_id: str
    result: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    error: ErrorBody | None = None


@dataclass(frozen=True, slots=True)
class OperationResult:
    """A command result that can carry warnings or a partial-success status."""

    result: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    partial: bool = False


def _redact(value: Any) -> Any:
    try:
        from .security import redact_value

        return redact_value(value)
    except (ImportError, AttributeError):
        return value


@dataclass(slots=True)
class OutputContext:
    command: str
    profile: str
    json_mode: bool = False
    quiet: bool = False
    schema_version: str = "1"
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    console: Console = field(default_factory=lambda: Console(stderr=False))
    error_console: Console = field(default_factory=lambda: Console(stderr=True))

    def envelope(
        self,
        *,
        status: Literal["success", "partial", "error"],
        result: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
        error: ErrorBody | None = None,
    ) -> Envelope:
        return Envelope(
            command=self.command,
            status=status,
            profile=self.profile,
            request_id=self.request_id,
            result=_redact(result) if result is not None else {},
            warnings=_redact(warnings or []),
            error=_redact(error),
        )

    def emit_success(
        self, result: dict[str, Any] | None = None, warnings: list[str] | None = None
    ) -> None:
        envelope = self.envelope(status="success", result=result, warnings=warnings)
        self._emit(envelope)

    def emit_partial(self, result: dict[str, Any], warnings: list[str] | None = None) -> None:
        envelope = self.envelope(status="partial", result=result, warnings=warnings)
        self._emit(envelope)

    def emit_error(self, error: AppError) -> int:
        body = ErrorBody(
            code=error.code,
            message=str(_redact(error.message)),
            retryable=error.retryable,
            details=_redact(error.details),
        )
        envelope = self.envelope(status="error", error=body)
        self._emit(envelope)
        return int(error.exit_code)

    def progress(self, message: str) -> None:
        if not self.json_mode and not self.quiet:
            self.error_console.print(_redact(message))

    def _emit(self, envelope: Envelope) -> None:
        if self.json_mode:
            payload = envelope.model_dump(mode="json")
            sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
            sys.stdout.flush()
            return

        if envelope.status == "error" and envelope.error is not None:
            self.error_console.print(f"[red]{envelope.error.code}:[/red] {envelope.error.message}")
            return
        if envelope.status == "partial":
            self.console.print("[yellow]Completed with partial failures.[/yellow]")
        if envelope.result:
            self.console.print_json(data=envelope.result)
        for warning in envelope.warnings:
            self.error_console.print(f"[yellow]Warning:[/yellow] {warning}")


def internal_error(message: str) -> AppError:
    return AppError("INTERNAL_ERROR", message, ExitCode.INTERNAL, False, {})
