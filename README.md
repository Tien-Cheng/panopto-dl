# panopto-dl

`panopto-dl` is a local, policy-controlled CLI for discovering and downloading
Panopto recordings that the current account is authorized to stream. It combines
a dedicated browser profile, the Panopto extractor embedded in `yt-dlp`, durable
SQLite state, immutable download plans, and a versioned JSON interface for agents.

Version 0.1 targets NUS MediaWeb at `mediaweb.ap.panopto.com`, macOS, and Linux.
Named profiles keep the design usable with other Panopto sites and accounts.

> [!IMPORTANT]
> Use this tool only for recordings your account is currently authorized to
> access and only where local downloading is permitted. It does not grant a
> right to redistribute course material. It does not bypass authentication,
> DRM, expired access, or another account boundary.

## Requirements

- Python 3.12 or newer
- [`uv`](https://docs.astral.sh/uv/) for installation and development
- Google Chrome or Chromium installed on the host
- FFmpeg and FFprobe available on `PATH`
- A graphical desktop for the initial SSO and MFA login

The first login is headed. Later authentication checks and downloads are
headless, so a Linux server only needs its display or RDP session when a human
must sign in again. `panopto-dl` launches an installed system browser and does
not use Playwright's downloaded browser build.

Typical prerequisite installs are:

```console
# macOS with Homebrew
brew install uv ffmpeg
brew install --cask google-chrome

# Ubuntu or Debian, after installing uv and a supported Chrome/Chromium package
sudo apt-get install ffmpeg

# AlmaLinux, after enabling the organization's approved multimedia repository
sudo dnf install ffmpeg
```

On Linux, install Google Chrome or Chromium from a trusted repository supported
by the host. If browser auto-detection fails, pass its executable explicitly
when creating the profile, for example `--browser-executable
/usr/bin/google-chrome` or `--browser-executable /usr/bin/chromium`.

Confirm all local dependencies after profile setup:

```console
panopto-dl --profile PROFILE doctor
```

## Install

Install the published package as an isolated CLI tool:

```console
uv tool install panopto-dl-cli
uv tool ensurepath
# Open a new shell if this is the first tool installed with uv.
panopto-dl --version
```

The PyPI distribution is named `panopto-dl-cli` because `panopto-dl` was already
registered by an unrelated project. The command installed by this package is
still `panopto-dl`.

Every `v*` tag publishes the wheel and source distribution to PyPI and attaches
the same artifacts to its GitHub release. To install an exact version, run
`uv tool install panopto-dl-cli==0.1.0`.

You can also install a downloaded tagged wheel directly:

```console
uv tool install /path/to/panopto_dl_cli-0.1.0-py3-none-any.whl
```

Until a wheel is published, install from a repository checkout:

```console
cd /path/to/panopto-dl
uv tool install .
```

To replace an existing checkout installation after pulling changes:

```console
uv tool install --force .
```

The CLI stores configuration and state in platform-native application
directories. Media is written only below each profile's configured output root.
Do not copy profile state between people or accounts.

## First-time profile setup

The CLI does not assume an institution or create a `nus` profile implicitly. Create a
named profile before using commands that access Panopto. The first profile becomes
the default even if `--no-default` is passed. `--profile` remains optional after
you add more profiles; use it when you want to override the configured default.

For any Panopto-hosted site, provide the site explicitly:

```console
panopto-dl profile init university \
  --site-url 'https://example.panopto.com' \
  --timezone 'Area/City' \
  --output-root "$HOME/Lectures"
```

NUS is available as an explicit preset rather than a default profile:

```console
panopto-dl profile init university \
  --preset nus \
  --output-root "$HOME/Lectures"
```

The `nus` preset selects `https://mediaweb.ap.panopto.com`, `Asia/Singapore`, and
the system Chrome channel. The profile name remains the user's choice. Additional
institution presets can be added without changing profile-selection behavior. Use
`--browser-executable PATH` when the browser is installed somewhere unusual.

Open a desktop session on macOS, or a KDE/RDP session on the Linux VM, then run:

```console
panopto-dl auth login
```

Complete the site's SSO and MFA in the opened browser. Login succeeds only after
the tool verifies an authenticated Panopto folder request. Future checks are
headless:

```console
panopto-dl auth status
```

If that command reports `AUTH_REQUIRED`, repeat the headed login yourself.
Never send a password, MFA code, cookie, or browser directory to an agent.

## Discover recordings

Discover the accessible folder tree, inspect a recording, or enumerate one
folder. Inputs may come from Canvas CLI, but Canvas authentication and crawling
remain a separate concern.

```console
panopto-dl --profile PROFILE discover folders
panopto-dl --profile PROFILE discover folders --url 'STABLE_FOLDER_URL'
panopto-dl --profile PROFILE discover sessions 'FOLDER_ID_OR_URL'
panopto-dl --profile PROFILE inspect 'VIEWER_URL_OR_SESSION_UUID'
```

Viewer, Embed, and folder URLs must belong to the configured Panopto site. The
CLI does not accept arbitrary `yt-dlp` sites or unrestricted downloader flags.

## Register sources safely

A source is a stable Panopto folder ID plus a local alias. New sources default
to `auto_sync=false`, and their `not_before` timestamp is the registration time.
That prevents a newly registered course from downloading its whole history.

```console
panopto-dl --profile PROFILE source add 'FOLDER_ID_OR_URL' --alias cs1010s
panopto-dl --profile PROFILE source list
```

Grant unattended sync permission only as an explicit choice:

```console
panopto-dl --profile PROFILE source add 'FOLDER_ID_OR_URL' \
  --alias cs1010s \
  --auto-sync
```

To select an earlier safe boundary at registration:

```console
panopto-dl --profile PROFILE source add 'FOLDER_ID_OR_URL' \
  --alias cs1010s \
  --not-before '2026-08-01T00:00:00+08:00'
```

Source changes are mutating operations. An agent should add or remove a source
only when the user explicitly requests that exact change.

## Plan, approve, and apply

Planning does not download or apply media. It refreshes the safe session cache
and records the exact sessions, output paths, media policy, estimates, profile
fingerprint, and content hash in SQLite. Plans are immutable and expire after
30 minutes.

```console
# New recordings after a source's not-before boundary
panopto-dl --profile PROFILE plan --source cs1010s

# Explicit historical selections
panopto-dl --profile PROFILE plan --source cs1010s --backfill all
panopto-dl --profile PROFILE plan --source cs1010s --since '2026-08-01T00:00:00+08:00'
panopto-dl --profile PROFILE plan --source cs1010s --last 3

# One recording discovered through Canvas or Panopto
panopto-dl --profile PROFILE plan --target 'VIEWER_URL_OR_SESSION_UUID'
```

Review the plan, then apply that exact plan ID:

```console
panopto-dl --profile PROFILE apply PLAN_ID
```

`apply` rejects expired plans and plans whose profile configuration changed
after creation. Creating a fresh plan is required in either case.

For a person at a terminal, `download` is a convenience command. It creates and
displays a one-item plan, then prompts before applying it:

```console
panopto-dl --profile PROFILE download 'VIEWER_URL_OR_SESSION_UUID'
```

Machine callers cannot use `download`. They must use `plan`, show the plan to
the user, receive explicit confirmation for its ID, and then use `apply`.
When a human intentionally needs a separate revision of an already completed
session, `download --refresh` creates one instead of replacing the stored media.

## Synchronize approved sources

`sync` creates an auditable internal plan and applies it only to sources already
registered with automatic sync permission:

```console
panopto-dl --profile PROFILE sync
panopto-dl --profile PROFILE status
```

Completed session IDs are idempotent and are not silently replaced. A remote
deletion never removes local media. At most one mutating command runs per
profile; a competing mutation exits immediately with `BUSY`. Read-only status
and discovery remain available.

Default safeguards allow two media jobs, four metadata requests, one fragment
stream, 20 new sessions, and 50 GiB of estimates per run while preserving a
20 GiB free-space reserve. Disk space is monitored while downloads are active.

## Media policy and output

The default `lecture` policy prefers Panopto's combined podcast, then the best
compatible stream up to 1080p with H.264, AAC, and MP4 preference. It remuxes
when required but does not transcode by default. `audio` and `all-streams` are
available with `--media-profile` on `plan`.

Each recording receives a stable directory:

```text
<output-root>/<source-alias>/<local-date> - <safe-title> [<12-char-id>]/
  lecture.mp4
  captions.<language>.srt
  slides.mhtml
  metadata.json
```

Not every recording produces every artifact. Audio plus timed slides is kept as
native artifacts and marked `needs_composite`; version 0.1 does not reconstruct
a slide video. Downloads use same-filesystem partial files, resume where
supported, validate media with FFprobe, calculate SHA-256, and commit by atomic
rename.

## JSON API for agents

Global machine flags must appear before the command:

```console
panopto-dl --profile PROFILE --json --quiet --schema-version 1 status
```

The process writes exactly one JSON object to stdout and nothing to stderr. The
`profile` field remains a string in schema `1.0`; it is empty only when no profile
has been selected yet, such as a version response or a setup-required error:

```json
{
  "schema_version": "1.0",
  "command": "status",
  "status": "success",
  "profile": "PROFILE",
  "request_id": "uuid",
  "result": {},
  "warnings": [],
  "error": null
}
```

Statuses are `success`, `partial`, and `error`. Errors contain a symbolic code,
sanitized message, retryability, and safe details. Exit codes are:

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 2 | Usage or configuration |
| 3 | Authentication required |
| 4 | Policy denial or invalid plan |
| 5 | Remote or download failure |
| 6 | Partial success |
| 7 | Local I/O or disk failure |
| 8 | Profile mutation is busy |
| 9 | Internal error |
| 130 | Interrupted |

Signed media URLs, cookies, authentication headers, authenticated response
bodies, and browser-profile paths are excluded from public output, plans,
diagnostics, and logs.

## Hermes Agent integration

The repository includes a constrained Hermes skill at
[`skills/panopto-dl`](skills/panopto-dl). Install `panopto-dl` for the same Unix
account that runs Hermes, ensure its tool bin directory is on the service's
`PATH`, then copy the whole skill directory into the Hermes installation's
configured skills directory. Do not declare browser profiles, cookies, or
Panopto credentials as Hermes-managed files.

The wheel installs only the CLI. Wheel users should also download the matching
source distribution from the same tagged release and copy
`skills/panopto-dl/` from that archive. A repository checkout already contains
the skill.

The skill's helper:

- invokes typed argument arrays with `shell=False`;
- probes `panopto-dl --version --json` before use;
- rejects arbitrary flags and validates the full JSON envelope;
- keeps interactive login and source mutation outside the agent surface;
- requires a displayed plan and conversational confirmation before `apply`;
- treats long-running `apply` and `sync` operations as background processes.

For script-only scheduled sync, install the two fixed wrappers and configure a
non-secret profile name:

```console
install -d -m 0700 "$HOME/.hermes/scripts"
install -m 0700 skills/panopto-dl/scripts/panopto_agent.py \
  "$HOME/.hermes/scripts/panopto_agent.py"
install -m 0700 skills/panopto-dl/scripts/panopto_cron.py \
  "$HOME/.hermes/scripts/panopto-sync.py"
python3 "$HOME/.hermes/scripts/panopto-sync.py" --configure-profile PROFILE
```

Configure Hermes cron to execute `panopto-sync.py` with `no_agent=true`. A
successful tick is silent. Authentication, disk, partial, and terminal failures
emit one sanitized action line. Run one manual tick under the Hermes service
account before enabling the schedule.

## Security boundaries and non-goals

- Each named profile represents one person, one account, and one allowed site.
- Browser data is owner-only. Cookies exist outside the browser only in a
  temporary `0600` Netscape file that is deleted after use.
- `yt-dlp` native HTTP and HLS transports fetch network media. FFmpeg receives
  only local files for merge or remux work.
- Output paths cannot escape the configured root. There is no arbitrary
  `yt-dlp` option passthrough and no telemetry.
- Version 0.1 excludes transcription, built-in Canvas crawling, GUI, MCP,
  multi-user service, internal scheduling, notifications, DRM circumvention,
  access escalation, and automatic replacement of completed media.

Friends should receive only source code, tagged wheels, and setup instructions.
Never share profiles, SQLite databases, browser directories, downloaded media,
or authentication state.

## Development

```console
uv sync --all-groups
uv run pytest -m 'not integration and not private'
uv run ruff check .
uv run mypy src/panopto_dl
uv build
```

Public demo metadata, folder, caption, stream, and timed-slide tests are opt-in.
The normal recording can be overridden with another stable public Viewer URL:

```console
PANOPTO_DL_RUN_INTEGRATION=1 \
uv run pytest -m integration tests/test_integration_public.py

PANOPTO_DL_RUN_INTEGRATION=1 \
PANOPTO_DL_PUBLIC_TEST_URL='https://PUBLIC-SITE/Panopto/Pages/Viewer.aspx?id=UUID' \
uv run pytest -m integration tests/test_integration_public.py::test_public_viewer_metadata_contract
```

Authenticated NUS smoke tests are deliberately manual and must never create
committed fixtures. See [the private smoke-test checklist](docs/manual-testing.md).

## License

MIT
