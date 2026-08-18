# Bug report: panopto-dl auth probe returns false AUTHENTICATED (zero cookies)

**Status:** FIXED — `_probe_authenticated()` now requires at least one httpOnly cookie scoped to the Panopto base URL; regression coverage rejects zero-cookie and analytics-only contexts while accepting a real httpOnly session cookie.

**Repo:** `/home/hermes/projects/panopto-dl` (user's fork, branch `feat/agnostic-profile-setup` @ `8bd917f`)
**File:** `src/panopto_dl/browser.py` — `_probe_authenticated()` (and `status()` which uses it)

## Summary

On NUS's Panopto instance (`https://mediaweb.ap.panopto.com`), `panopto-dl auth status` reports `AUTHENTICATED` even when the browser profile holds **zero cookies** — i.e. there is no real logged-in session at all. The probe is a false positive, which cascades into confusing downstream failures.

## Root cause

`_probe_authenticated(context)` POSTs to `{base}/Panopto/Services/Data.svc/GetSessions` and then treats the request as authenticated if the response:

1. is not 401/403, and
2. parses as JSON that unwraps to a mapping containing any of `Results` / `Subfolders` / `TotalResultCount` / `TotalNumber` / `MoreData`.

NUS's Panopto returns **HTTP 200 with a well-formed body** (`{"d":{"Results":[],"TotalNumber":0,...}}`) for *completely anonymous, no-cookie* requests. So the shape check passes with zero auth state. Verified with a bare `curl` (no cookies) returning exactly that body.

## Observable symptoms

- `panopto-dl --profile nus auth status` → `"authenticated": true`, reason `AUTHENTICATED`.
- Browser profile `~/.local/share/panopto-dl/profiles/nus/browser/` has 0 cookies (`context.cookies()` returns empty for all domains). `BrowserSession.cookies_file()` therefore writes an **empty Netscape cookie file** (82 bytes, header only).
- **`auth login` is also broken by this.** `login()` (browser.py line 84) opens a headed browser, then loops on `_probe_authenticated`. Because the probe returns True immediately for anonymous sessions, `login()` returns `AUTHENTICATED` in ~15s **without ever waiting for the user to complete SSO**. A real login can't be established via `auth login` until the probe is fixed. (Reproduced: login exited in 17s, only wrote `_ga`/`_gid` analytics cookies.)
- `panopto-dl --profile nus inspect -- '<viewer-url>'` → `AUTH_REQUIRED: Interactive authentication is required` (exit 3). This is because the real auth check happens inside yt-dlp, which is handed the empty cookie file and errors:
  `ERROR: [Panopto] <id>: This video is only available for registered users. Use --cookies-from-browser or --cookies for the authentication.`
  That yt-dlp error is mapped to `AuthenticationError` via `_translate_yt_dlp_error` in `src/panopto_dl/panopto.py`.
- Root-level `discover folders` returns 0 folders (anonymous session has no folders).

## Reproduction (on this host)

1. Ensure `~/.local/share/panopto-dl/profiles/nus/browser/` has no real session.
2. `panopto-dl --profile nus auth status` → false AUTHENTICATED.
3. Inspect any real Viewer URL → AUTH_REQUIRED.
4. Direct yt-dlp with the generated cookie file → "only available for registered users".

## Status
FIXED (refined) — the probe now requires an httpOnly cookie, so `_ga`/`_gid` alone cannot authenticate the context.

## Refinement required (verified against the live NUS profile)

The first-pass fix makes `_probe_authenticated` return `bool(context.cookies([self.base_url]))` — "at least one cookie." But **Google Analytics cookies defeat it.** The NUS profile currently holds only `_ga` and `_gid` (both on `.panopto.com`, both `httpOnly=False`), left over from the broken `auth login` attempt. Those are scoped to the Panopto domain and pass `cookies([base_url])`, so `auth status` still reports `AUTHENTICATED` with no real session.

A genuine authenticated Panopto session sets an httpOnly session/auth cookie (typically `ASP.NET_SessionId` and/or `.ASPXAUTH`). The probe should require evidence of a real session cookie, not just *any* cookie.

Recommended refinement (pick one, or combine):
1. **Require at least one httpOnly cookie** in `context.cookies([self.base_url])`. GA/analytics cookies are never httpOnly; Panopto's real session cookie is. Simple and effective.
2. **Filter out known analytics/third-party cookie names** (`_ga`, `_gid`, `_gat`, `_ga_*`, `__utm*`, `_pk_*`, etc.) before counting.
3. Require a specific Panopto session-cookie name (`ASP.NET_SessionId` and/or `.ASPXAUTH`) to be present.

Keep the regression tests: they already prove non-empty `Results` with zero cookies is not authenticated. Add a case proving **non-empty `Results` with only GA-analytics cookies is also NOT authenticated**, and that a real (httpOnly) session cookie does authenticate.

## Constraints

- The probe must remain cheap and headless-safe (it already runs inside a headless persistent context).
- Don't break instances where GetSessions does gate on auth (returns 401/403 for anonymous) — the new logic must be additive: it should return authenticated **only** when there's real evidence (non-empty results AND/OR cookies), never regress the current false positive into a false negative for genuinely-logged-in users.
- Keep cookie contents out of any error messages (the existing redactor handles this).

## Verification

After the fix, on this host, `auth status` should report `AUTH_REQUIRED` (not AUTHENTICATED) while the profile is logged out. After a real headed login, `auth status` should report AUTHENTICATED **and** `cookies_file()` should yield a non-empty file, and `inspect`/`plan`/`apply` should work against real session URLs. Add/adjust unit tests in `tests/` accordingly (mock the GetSessions response + cookie set).

---

# Follow-up: session cookie is NOT persisted — headless auth still fails after login (FIXED)

**Status:** FIXED — `auth login` now re-issues session-scoped cookies with a 30-day expiry so Chromium writes them to the persistent profile store. Verified: after a headed login, `auth status` (fresh headless context) returns `AUTHENTICATED`.

## The second bug (discovered during E2E verification)

After the probe fix, `auth login` correctly reported `AUTHENTICATED` (a real `.ASPXAUTH` httpOnly cookie existed in the live headed browser), **but a fresh `auth status` in a separate headless process still returned `AUTH_REQUIRED`.**

## Root cause

NUS SSO (ADFS / `vafs.u.nus.edu`) issues the Panopto auth cookie **`.ASPXAUTH` as a session cookie**: `httpOnly=True` but `exp=-1` (no expiry). Chromium only flushes cookies that carry an `expires` to the on-disk `Default/Cookies` store; **session cookies live in memory and are dropped when the browser closes.**

Empirically proven with a controlled test on the profile: a cookie written with `expires=now+30d` **survived** a browser restart; an identical cookie written without an expiry was **lost**. The on-disk store held only the persistent analytics (`_ga`, `_gid`) + `UserSettings` cookies — never `.ASPXAUTH`. So every later headless open (auth status, inspect, sync) started logged-out.

This is exactly the scenario the README assumes away ("The first login is headed. Later authentication checks and downloads are headless"): it presumes the auth cookie persists, which NUS's SSO does not provide.

## Fix

`browser.py` `login()`: once `_probe_authenticated` confirms a real session, call a new `_persist_session_cookies(context)` that reads the live cookies for `base_url` and re-issues any **session-scoped** ones (`expires` <= 0) with a fixed 30-day lifetime via `context.add_cookies()`. Persistent cookies keep their original lifetime. The 30-day value only governs browser-side persistence; the SSO provider may revoke the underlying session sooner (handled downstream by re-login).

## Related: folder discovery returns `recorded_at: null` → sync always empty (FIXED in same commit)

`plan`/`sync` for a registered source called `discover_sessions(folder_id)` with default `hydrate=False`. The yt-dlp flat-playlist entries omit `timestamp`, so every session's `recorded_at` was `None`, and `_selected_by_history` dropped them all under the `not_before` cutoff — plain `sync` returned 0 items even for a source with a downloadable lecture. Only `--backfill all` (which bypasses the cutoff) worked.

Fix: `service.py` plan/sync now calls `discover_sessions(folder_id, hydrate=True)`, which runs a per-session `inspect` and populates `recorded_at`. Verified on the live NUS profile: `hydrate=False` → `rec:None`; `hydrate=True` → `rec:2026-10-03 03:13:32+00:00`. `tests/test_service.py` `FakeClient.discover_sessions` updated to accept and honor `hydrate`.

## Verification (this host)

- `panopto-dl --profile nus auth status` (fresh process) → `AUTHENTICATED`, exit 0, after a single headed login.
- Cookie DB `Default/Cookies` now contains `.ASPXAUTH` with `has_expires=1` (plus the session-scoped NUS cookies still stored session-only).
- `inspect` → L01 metadata; `plan --session` → plan; `apply` → `lecture.mp4` (238,635,912 bytes, sha256 verified), duration 5999.95s.
- `sync --source cs2106` → returns empty **as intended** now that L01 is `complete` (`refresh=False` excludes terminal sessions); a future new lecture will hydrate with `recorded_at` and be planned.
- Commit `779eac8`; 153 passed, ruff + mypy clean.

