"""Typer command surface for humans and machine callers."""

from __future__ import annotations

import sqlite3
import sys
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from typer import _click as click

from . import __version__
from .config import (
    PROFILE_PRESETS,
    ConfigError,
    ConfigManager,
    ProfileConfig,
    validate_profile_name,
)
from .database import DatabaseError
from .domain import MediaPolicy
from .errors import AppError, ExitCode, LocalIOError, PolicyError, UsageError
from .output import OperationResult, OutputContext, internal_error
from .service import AppService

app = typer.Typer(
    name="panopto-dl",
    help="Discover and download authorized Panopto recordings safely.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
profile_app = typer.Typer(help="Manage named site profiles.", no_args_is_help=True)
auth_app = typer.Typer(help="Manage the profile's browser authentication.", no_args_is_help=True)
discover_app = typer.Typer(help="Discover accessible Panopto content.", no_args_is_help=True)
source_app = typer.Typer(help="Manage automatic-sync source folders.", no_args_is_help=True)
app.add_typer(profile_app, name="profile")
app.add_typer(auth_app, name="auth")
app.add_typer(discover_app, name="discover")
app.add_typer(source_app, name="source")


@dataclass(frozen=True, slots=True)
class GlobalOptions:
    profile: str | None
    json_mode: bool
    quiet: bool
    schema_version: str


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    profile: Annotated[
        str | None,
        typer.Option("--profile", help="Named site profile; defaults to configured profile."),
    ] = None,
    json_mode: Annotated[
        bool,
        typer.Option("--json", help="Emit one versioned JSON document."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", help="Suppress human progress and log output."),
    ] = False,
    schema_version: Annotated[
        str,
        typer.Option("--schema-version", help="Machine schema major version."),
    ] = "1",
    version: Annotated[
        bool,
        typer.Option("--version", help="Show the installed version and exit.", is_eager=True),
    ] = False,
) -> None:
    try:
        if profile is not None:
            profile = validate_profile_name(profile)
    except ConfigError as error:
        raise typer.BadParameter("Invalid profile name", param_hint="--profile") from error
    options = GlobalOptions(profile, json_mode, quiet or json_mode, schema_version)
    ctx.obj = options
    if version:
        output = _output(options, "version")
        if schema_version not in {"1", "1.0"}:
            _fail(output, UsageError("Unsupported schema version", schema_version=schema_version))
        output.emit_success({"version": __version__})
        raise typer.Exit(ExitCode.SUCCESS)


def _options(ctx: typer.Context) -> GlobalOptions:
    value = ctx.find_root().obj
    if not isinstance(value, GlobalOptions):
        return GlobalOptions(None, False, False, "1")
    return value


def _output(options: GlobalOptions, command: str) -> OutputContext:
    return OutputContext(
        command=command,
        profile=options.profile or "",
        json_mode=options.json_mode,
        quiet=options.quiet,
        schema_version=options.schema_version,
    )


def _fail(output: OutputContext, error: AppError) -> None:
    raise typer.Exit(output.emit_error(error))


def _run(
    ctx: typer.Context,
    command: str,
    operation: Callable[[OutputContext], dict[str, object] | OperationResult],
) -> dict[str, object] | OperationResult:
    output = _output(_options(ctx), command)
    try:
        if output.schema_version not in {"1", "1.0"}:
            raise UsageError("Unsupported schema version", schema_version=output.schema_version)
        result = operation(output)
        if isinstance(result, OperationResult):
            if result.partial:
                output.emit_partial(result.result, list(result.warnings))
                raise typer.Exit(ExitCode.PARTIAL)
            output.emit_success(result.result, list(result.warnings))
        else:
            output.emit_success(result)
        return result
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        error = AppError(
            "INTERRUPTED",
            "Operation interrupted; partial files remain resumable",
            ExitCode.INTERRUPTED,
            True,
            {},
        )
        _fail(output, error)
    except AppError as error:
        _fail(output, error)
    except ConfigError as error:
        _fail(output, UsageError(str(error), code="CONFIG_ERROR"))
    except ValidationError:
        _fail(output, UsageError("Configuration validation failed", code="CONFIG_ERROR"))
    except (DatabaseError, sqlite3.Error):
        _fail(output, LocalIOError("Local state could not be updated", code="DATABASE_ERROR"))
    except OSError:
        _fail(output, LocalIOError("A local filesystem operation failed"))
    except Exception:  # pragma: no cover - final public safety boundary
        _fail(output, internal_error("Unexpected internal failure"))
    raise AssertionError("unreachable")


def _service(ctx: typer.Context, output: OutputContext) -> AppService:
    options = _options(ctx)
    manager = ConfigManager()
    profile = manager.get_profile(options.profile)
    output.profile = profile.name
    return AppService.open(profile.name, manager, output.progress)


@profile_app.command("init")
def profile_init(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="New profile name.")],
    output_root: Annotated[Path, typer.Option("--output-root", help="Media output root.")],
    preset: Annotated[
        str | None,
        typer.Option(
            "--preset",
            help=f"Built-in site preset ({', '.join(sorted(PROFILE_PRESETS))}).",
        ),
    ] = None,
    site_url: Annotated[
        str | None, typer.Option("--site-url", help="Panopto HTTPS origin.")
    ] = None,
    timezone: Annotated[
        str | None, typer.Option("--timezone", help="IANA display timezone.")
    ] = None,
    browser_channel: Annotated[
        str | None,
        typer.Option("--browser-channel", help="Playwright browser channel."),
    ] = None,
    browser_executable: Annotated[
        Path | None,
        typer.Option("--browser-executable", help="Installed Chrome/Chromium path."),
    ] = None,
    make_default: Annotated[
        bool | None,
        typer.Option(
            "--default/--no-default",
            help="Make this the default profile; the first profile is always the default.",
        ),
    ] = None,
) -> None:
    def operation(output: OutputContext) -> dict[str, object]:
        profile = ConfigManager().init_profile(
            name,
            output_root=output_root,
            preset=preset,
            site_url=site_url,
            timezone=timezone,
            browser_channel=browser_channel,
            browser_executable=browser_executable,
            make_default=make_default,
        )
        output.profile = profile.name
        return _public_profile(profile)

    _run(ctx, "profile init", operation)


@profile_app.command("list")
def profile_list(ctx: typer.Context) -> None:
    _run(
        ctx,
        "profile list",
        lambda _: {"profiles": [_public_profile(item) for item in ConfigManager().list_profiles()]},
    )


@profile_app.command("show")
def profile_show(
    ctx: typer.Context,
    name: Annotated[str | None, typer.Argument(help="Profile name.")] = None,
) -> None:
    def operation(output: OutputContext) -> dict[str, object]:
        profile = ConfigManager().get_profile(name or _options(ctx).profile)
        output.profile = profile.name
        return _public_profile(profile)

    _run(ctx, "profile show", operation)


def _public_profile(profile: ProfileConfig) -> dict[str, object]:
    return {
        "name": profile.name,
        "site_url": profile.site_url,
        "timezone": profile.timezone,
        "output_root": str(profile.output_root),
        "media_policy": profile.media_policy.value,
        "limits": profile.limits.model_dump(mode="json"),
    }


@auth_app.command("login")
def auth_login(
    ctx: typer.Context,
    timeout: Annotated[
        int,
        typer.Option("--timeout", min=30, help="Login timeout in seconds."),
    ] = 600,
) -> None:
    _run(ctx, "auth login", lambda output: _service(ctx, output).auth_login(timeout))


@auth_app.command("status")
def auth_status(ctx: typer.Context) -> None:
    _run(ctx, "auth status", lambda output: _service(ctx, output).auth_status())


@auth_app.command("logout")
def auth_logout(ctx: typer.Context) -> None:
    _run(ctx, "auth logout", lambda output: _service(ctx, output).auth_logout())


@discover_app.command("folders")
def discover_folders(
    ctx: typer.Context,
    url: Annotated[str | None, typer.Option("--url", help="Stable folder URL.")] = None,
) -> None:
    _run(ctx, "discover folders", lambda output: _service(ctx, output).discover_folders(url))


@discover_app.command("sessions")
def discover_sessions(
    ctx: typer.Context,
    folder: Annotated[
        str | None,
        typer.Argument(help="Folder ID, alias, or stable URL."),
    ] = None,
    sources: Annotated[
        list[str] | None,
        typer.Option("--source", help="Registered source alias; repeatable."),
    ] = None,
) -> None:
    def operation(output: OutputContext) -> dict[str, object]:
        selectors = ([folder] if folder else []) + (sources or [])
        if not selectors:
            raise UsageError("A folder or registered source is required")
        service = _service(ctx, output)
        results = [service.discover_sessions(selector) for selector in selectors]
        if len(results) == 1:
            return results[0]
        sessions_by_id: dict[str, object] = {}
        for result in results:
            raw_sessions = result.get("sessions", [])
            if not isinstance(raw_sessions, list):
                continue
            for session in raw_sessions:
                if not isinstance(session, dict):
                    continue
                session_id = session.get("session_id")
                if isinstance(session_id, str):
                    sessions_by_id[session_id] = session
        return {
            "selectors": selectors,
            "session_count": len(sessions_by_id),
            "sessions": list(sessions_by_id.values()),
        }

    _run(ctx, "discover sessions", operation)


@source_app.command("add")
def source_add(
    ctx: typer.Context,
    folder: Annotated[str, typer.Argument(help="Stable Panopto folder ID or URL.")],
    alias: Annotated[str, typer.Option("--alias", help="Safe local source alias.")],
    auto_sync: Annotated[
        bool,
        typer.Option("--auto-sync", help="Permit unattended synchronization."),
    ] = False,
    not_before: Annotated[
        datetime | None,
        typer.Option("--not-before", help="Earliest recording time, ISO 8601."),
    ] = None,
) -> None:
    _run(
        ctx,
        "source add",
        lambda output: _service(ctx, output).source_add(
            folder,
            alias=alias,
            auto_sync=auto_sync,
            not_before=not_before,
        ),
    )


@source_app.command("list")
def source_list(ctx: typer.Context) -> None:
    _run(ctx, "source list", lambda output: _service(ctx, output).source_list())


@source_app.command("remove")
def source_remove(
    ctx: typer.Context,
    source: Annotated[str, typer.Argument(help="Source alias or numeric ID.")],
) -> None:
    _run(ctx, "source remove", lambda output: _service(ctx, output).source_remove(source))


@app.command("inspect")
def inspect_session(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Stable Viewer URL or session UUID.")],
) -> None:
    _run(ctx, "inspect", lambda output: _service(ctx, output).inspect(target))


@app.command("plan")
def plan_command(
    ctx: typer.Context,
    sources: Annotated[
        list[str] | None,
        typer.Option("--source", help="Source alias; repeat for more than one."),
    ] = None,
    sessions: Annotated[
        list[str] | None,
        typer.Option(
            "--session",
            "--target",
            help="One-off Viewer URL or ID; repeatable.",
        ),
    ] = None,
    backfill: Annotated[
        str | None,
        typer.Option("--backfill", help="Historical selection: all."),
    ] = None,
    since: Annotated[
        datetime | None,
        typer.Option("--since", help="Historical recordings on or after this timestamp."),
    ] = None,
    last: Annotated[int | None, typer.Option("--last", min=1, help="Latest N recordings.")] = None,
    media_policy: Annotated[
        MediaPolicy | None,
        typer.Option(
            "--media-policy",
            "--media-profile",
            help="lecture, audio, or all-streams.",
        ),
    ] = None,
) -> None:
    _run(
        ctx,
        "plan",
        lambda output: _service(ctx, output).create_plan(
            sources=sources or [],
            sessions=sessions or [],
            backfill=backfill,
            since=since,
            last=last,
            media_policy=media_policy,
        ),
    )


@app.command("apply")
def apply_command(
    ctx: typer.Context,
    plan_id: Annotated[str, typer.Argument(help="Immutable approved plan ID.")],
) -> None:
    _run(ctx, "apply", lambda output: _service(ctx, output).apply_plan(plan_id))


@app.command("download")
def download_command(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Stable Viewer URL or session UUID.")],
    refresh: Annotated[
        bool,
        typer.Option("--refresh", help="Create a new revision of completed media."),
    ] = False,
    media_policy: Annotated[
        MediaPolicy | None,
        typer.Option("--media-policy", help="lecture, audio, or all-streams."),
    ] = None,
) -> None:
    options = _options(ctx)
    if options.json_mode:
        _run(
            ctx,
            "download",
            lambda _: (_ for _ in ()).throw(
                PolicyError(
                    "Machine callers must use plan followed by apply",
                    code="PLAN_REQUIRED",
                )
            ),
        )
        return

    def operation(output: OutputContext) -> OperationResult:
        service = _service(ctx, output)
        plan = service.create_plan(
            sources=[],
            sessions=[target],
            backfill=None,
            since=None,
            last=None,
            media_policy=media_policy,
            refresh=refresh,
        )
        plan_id = str(plan["plan_id"])
        estimate = plan.get("estimated_bytes")
        output.progress(f"Plan ID: {plan_id}")
        output.progress(f"Expires: {plan['expires_at']}")
        output.progress(f"Media policy: {plan['media_policy']}")
        output.progress(f"Items: {plan['item_count']}")
        output.progress(f"Estimated bytes: {estimate if estimate is not None else 'unknown'}")
        raw_items = plan.get("items", [])
        if isinstance(raw_items, list):
            for item in raw_items:
                if isinstance(item, dict):
                    output.progress(
                        f"  {item.get('session_id')}: {item.get('output_path')} "
                        f"({item.get('estimated_bytes') or 'unknown'} bytes)"
                    )
        if not typer.confirm("Apply this exact download plan?"):
            raise PolicyError("Download plan was not approved", code="PLAN_NOT_APPROVED")
        result = service.apply_plan(plan_id)
        return result if isinstance(result, OperationResult) else OperationResult(result=result)

    _run(ctx, "download", operation)


@app.command("sync")
def sync_command(
    ctx: typer.Context,
    sources: Annotated[
        list[str] | None,
        typer.Option("--source", help="Limit sync to an auto-sync source alias."),
    ] = None,
) -> None:
    _run(ctx, "sync", lambda output: _service(ctx, output).sync(sources or []))


@app.command("status")
def status_command(ctx: typer.Context) -> None:
    _run(ctx, "status", lambda output: _service(ctx, output).status())


@app.command("doctor")
def doctor_command(ctx: typer.Context) -> None:
    _run(ctx, "doctor", lambda output: _service(ctx, output).doctor())


def main() -> None:
    try:
        exit_code = app(standalone_mode=False)
        if isinstance(exit_code, int) and exit_code != 0:
            raise SystemExit(exit_code)
    except click.ClickException as error:
        if "--json" not in sys.argv[1:]:
            error.show()
            raise SystemExit(error.exit_code) from None
        options = _machine_options_from_argv(sys.argv[1:])
        output = _output(options, _requested_command(sys.argv[1:]))
        raise SystemExit(
            output.emit_error(UsageError("Invalid command arguments", code="INVALID_INPUT"))
        ) from None
    except click.exceptions.Abort:
        if "--json" not in sys.argv[1:]:
            raise SystemExit(ExitCode.INTERRUPTED) from None
        options = _machine_options_from_argv(sys.argv[1:])
        output = _output(options, _requested_command(sys.argv[1:]))
        interrupted = AppError(
            "INTERRUPTED",
            "Operation interrupted; partial files remain resumable",
            ExitCode.INTERRUPTED,
            True,
            {},
        )
        raise SystemExit(output.emit_error(interrupted)) from None


def _machine_options_from_argv(arguments: list[str]) -> GlobalOptions:
    profile = None
    for index, value in enumerate(arguments):
        if value == "--profile" and index + 1 < len(arguments):
            candidate = arguments[index + 1]
            if candidate and not candidate.startswith("-"):
                with suppress(ConfigError):
                    profile = validate_profile_name(candidate)
        elif value.startswith("--profile="):
            candidate = value.partition("=")[2]
            with suppress(ConfigError):
                profile = validate_profile_name(candidate)
    schema = "1"
    for index, value in enumerate(arguments):
        if value == "--schema-version" and index + 1 < len(arguments):
            schema = arguments[index + 1]
        elif value.startswith("--schema-version="):
            schema = value.partition("=")[2]
    return GlobalOptions(profile, True, True, schema)


def _requested_command(arguments: list[str]) -> str:
    groups = {"profile", "auth", "discover", "source"}
    leaves = {"apply", "doctor", "download", "inspect", "plan", "status", "sync"}
    for index, value in enumerate(arguments):
        if value in groups:
            if index + 1 < len(arguments) and arguments[index + 1].isalpha():
                return f"{value} {arguments[index + 1]}"
            return value
        if value in leaves:
            return value
    return "cli"


if __name__ == "__main__":  # pragma: no cover
    main()
