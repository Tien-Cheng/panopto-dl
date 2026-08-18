# Bug report: panopto-dl auth probe returns false AUTHENTICATED (zero cookies)

**Status:** FIXED — `_probe_authenticated()` now requires at least one cookie scoped to the Panopto base URL; regression coverage verifies that even non-empty results cannot authenticate a zero-cookie context.

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

## Suggested fix

`_probe_authenticated` should require positive evidence of an authenticated session, not just a well-formed response. Options, in order of preference:

1. **Require a non-empty session.** Treat the probe as authenticated only if the unwrapped body is non-empty in a meaningful way — e.g. `Results`/`Subfolders` contains at least one entry, **and** at least one Panopto session cookie (`ASP.NET_SessionId`, `.ASPXAUTH`, or a Panopto auth cookie) is present in `context.cookies([self.base_url])`.
2. **Check cookies directly.** The most robust signal: `len(context.cookies([self.base_url])) > 0` (or presence of a specific auth cookie). A real logged-in Panopto session persists session cookies; an anonymous session has none. Since `cookies_file()` already depends on `context.cookies(...)` being non-empty, the probe should share that signal so `auth status` and `inspect` agree.
3. If GetSessions is inherently anonymous-friendly on some instances, probe a different, auth-gated endpoint, or fetch a specific folder/session that only an authenticated user can see.

## Constraints

- The probe must remain cheap and headless-safe (it already runs inside a headless persistent context).
- Don't break instances where GetSessions does gate on auth (returns 401/403 for anonymous) — the new logic must be additive: it should return authenticated **only** when there's real evidence (non-empty results AND/OR cookies), never regress the current false positive into a false negative for genuinely-logged-in users.
- Keep cookie contents out of any error messages (the existing redactor handles this).

## Verification

After the fix, on this host, `auth status` should report `AUTH_REQUIRED` (not AUTHENTICATED) while the profile is logged out. After a real headed login, `auth status` should report AUTHENTICATED **and** `cookies_file()` should yield a non-empty file, and `inspect`/`plan`/`apply` should work against real session URLs. Add/adjust unit tests in `tests/` accordingly (mock the GetSessions response + cookie set).
