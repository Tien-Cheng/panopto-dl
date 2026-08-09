# Private NUS and AlmaLinux smoke testing

This checklist validates behaviors that cannot be exercised safely in public CI.
Run it only with an account that is allowed to stream the selected recordings.
Use a disposable output root and recordings that the tester may download.

Do not record or commit screenshots, terminal transcripts, HTTP captures,
browser data, cookies, signed URLs, course names, folder names, lecture titles,
authenticated response bodies, media files, or private test output. A test report
should contain only the build version, platform, date, and `PASS`, `FAIL`, or
`BLOCKED` for each numbered case.

## Release gate

Before testing, install the candidate wheel through `uv` for the same Unix
account that owns the dedicated browser profile:

```console
uv tool install --force dist/panopto_dl_cli-0.1.0-py3-none-any.whl
panopto-dl --version
ffmpeg -version
ffprobe -version
```

Install a system Google Chrome or Chromium build. The application deliberately
does not use Playwright's downloaded browser. On AlmaLinux, perform the browser
tests from the actual Hermes VM, not only from a container. The release is
blocked if headed login or the later headless status check fails on that VM.

Create a test profile with a new, disposable media directory:

```console
panopto-dl profile init nus-smoke \
  --preset nus \
  --output-root '/absolute/private/test-output' \
  --browser-executable '/absolute/path/to/chrome-or-chromium'
panopto-dl --profile nus-smoke doctor
```

Repeat profile creation separately on macOS and AlmaLinux. Do not copy a browser
directory, configuration file, or SQLite database between machines.

## 1. Interactive NUS login on macOS and AlmaLinux

On each platform:

1. Open the local desktop, or KDE through RDP on AlmaLinux.
2. Run `panopto-dl --profile nus-smoke auth login`.
3. Complete NUS SSO and MFA directly in the browser window.
4. Confirm the command returns success only after Panopto folder access works.
5. Close the launched browser if it remains open.

Pass criteria:

- No credential or MFA value is requested by the CLI or printed to the terminal.
- The browser profile is dedicated to `panopto-dl` and owner-only.
- Successful login is based on an authenticated Panopto request, not merely on
  reaching a post-login-looking page.

## 2. Subsequent headless authentication check

Close the desktop browser window, then run outside the interactive session when
possible:

```console
panopto-dl --profile nus-smoke auth status
panopto-dl --profile nus-smoke --json --quiet --schema-version 1 auth status
```

Pass criteria:

- Both checks succeed without opening a visible window or requesting MFA.
- Machine mode emits exactly one JSON object on stdout and nothing on stderr.
- The JSON contains no cookies, headers, signed URLs, browser paths, or response
  bodies.

This is the early AlmaLinux browser-backend acceptance gate. If the actual VM
cannot pass it with its installed Chrome or Chromium, stop the release and
evaluate replacement of the browser boundary. Do not ship two browser backends.

## 3. Root and folder discovery

Run root discovery, then choose one authorized low-volume folder by its stable
ID or stable Panopto folder URL:

```console
panopto-dl --profile nus-smoke discover folders
panopto-dl --profile nus-smoke discover sessions 'FOLDER_ID_OR_URL'
panopto-dl --profile nus-smoke inspect 'VIEWER_URL_OR_SESSION_UUID'
```

Pass criteria:

- Root discovery includes nested folders and completes pagination.
- Folder discovery returns each recording once by stable UUID.
- Inspection exposes safe metadata, captions, chapters, and format summaries
  when present, but no media or caption download URL.
- An URL from another Panopto account boundary or host is rejected.

Do not paste discovery output into an issue or test report.

## 4. One approved lecture download

Register one source without automatic sync. Its default `not_before` should be
the registration time:

```console
panopto-dl --profile nus-smoke source add 'FOLDER_ID_OR_URL' --alias smoke-source
panopto-dl --profile nus-smoke source list
panopto-dl --profile nus-smoke plan \
  --target 'VIEWER_URL_OR_SESSION_UUID' \
  --media-profile lecture
panopto-dl --profile nus-smoke apply PLAN_ID
```

Pass criteria:

- The plan shows one exact session, a contained output path, policy, estimate,
  content hash, and expiry without exposing any signed URL.
- The plan is applied only by its exact ID and only before expiry.
- Network transfer is performed by `yt-dlp` native HTTP or HLS transport.
- FFmpeg command arguments contain only local paths.
- The final media passes FFprobe, has a stored SHA-256, and appears only after an
  atomic rename from its same-filesystem partial path.
- Metadata keeps the full session UUID. The directory name contains the local
  date, safe title, and 12-character identifier.

Also inspect an audio plus timed-slides recording if one is safely available.
It should preserve its native artifacts and finish as `needs_composite` rather
than silently transcoding or synthesizing a video.

## 5. Interrupted download resume

Choose a recording large enough to leave a partial file:

1. Create and approve a one-item plan.
2. Start `apply` and interrupt it with Ctrl-C during media transfer.
3. Confirm exit code 130 and a safe interruption message.
4. Check that the sibling `.part` staging directory remains on the same output filesystem.
5. Retry through the CLI's reported safe path, creating a new plan if required.

Pass criteria:

- The retry resumes supported media rather than discarding valid partial data.
- No completed artifact is committed before FFprobe and hash validation.
- The database does not mark the session complete after the interruption.

Do not inspect or copy the temporary cookie file during this test.

## 6. Idempotent sync

Use a fresh source selected specifically for this test. Register it with explicit
automatic permission and a safe `not_before` boundary:

```console
panopto-dl --profile nus-smoke source add 'SECOND_FOLDER_ID_OR_URL' \
  --alias smoke-sync \
  --auto-sync \
  --not-before 'SAFE_ISO_8601_TIMESTAMP'
panopto-dl --profile nus-smoke sync --source smoke-sync
panopto-dl --profile nus-smoke sync --source smoke-sync
panopto-dl --profile nus-smoke status
```

Pass criteria:

- Each sync creates an auditable internal plan.
- The second sync does not download or replace a completed session ID.
- Local files remain when a remote recording is absent.
- Starting a second mutating command concurrently returns `BUSY` immediately;
  `status` remains readable during the active sync.

## 7. Expired-session recovery through RDP

Clear the dedicated session to simulate expiration:

```console
panopto-dl --profile nus-smoke auth logout
panopto-dl --profile nus-smoke auth status
panopto-dl --profile nus-smoke sync --source smoke-sync
```

Pass criteria before recovery:

- `auth status` and `sync` return `AUTH_REQUIRED` with exit code 3. General
  `status` remains readable and reports the authentication failure safely.
- No account credential, cookie, sign-in redirect, or authenticated body appears
  in either human or JSON output.

Open KDE through RDP, repeat headed `auth login`, disconnect RDP, and run the
headless status and sync again. Both should recover without changing source
configuration or exposing authentication state.

## 8. Hermes plan, approval, background apply, and cron

Install the repository's `skills/panopto-dl` directory in the Hermes skills
location. Ensure `panopto-dl` is on `PATH` for the Hermes service account.

From a Hermes conversation:

1. Ask for authentication status and discovery.
2. Ask to plan one exact authorized recording.
3. Verify Hermes displays the plan ID, item count, estimate, policy, and expiry.
4. Do not approve initially. Verify that no `apply` process starts.
5. Explicitly approve the displayed plan ID.
6. Verify `apply PLAN_ID` starts as a background process and is polled to a
   semantic `success`, `partial`, or `error` result.
7. Ask for a source mutation without naming the exact change. Verify Hermes does
   not add or remove anything.

Install the fixed scheduling scripts:

```console
install -d -m 0700 "$HOME/.hermes/scripts"
install -m 0700 skills/panopto-dl/scripts/panopto_agent.py \
  "$HOME/.hermes/scripts/panopto_agent.py"
install -m 0700 skills/panopto-dl/scripts/panopto_cron.py \
  "$HOME/.hermes/scripts/panopto-sync.py"
python3 "$HOME/.hermes/scripts/panopto-sync.py" --configure-profile nus-smoke
python3 "$HOME/.hermes/scripts/panopto-sync.py"
```

Pass criteria:

- The cron entry is script-only and configured with `no_agent=true`.
- A successful manual tick emits no output.
- Authentication, disk, partial, and terminal failures emit one sanitized action
  line without a title, course, output path, URL, cookie, or response body.
- The helper invokes a fixed typed argument array with `shell=False` and rejects
  arbitrary flags.

## Cleanup

After recording only the safe PASS/FAIL report:

```console
panopto-dl --profile nus-smoke auth logout
```

Remove the disposable profile state and test output manually only after resolving
their exact platform-native paths. Prefer moving them to trash. Never use a broad
recursive deletion command, an unresolved environment variable, `$HOME`, `~`, or
a filesystem root as the deletion target.
