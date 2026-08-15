---
name: panopto-dl
description: Plan, sync, and inspect authorized Panopto recordings.
license: MIT
compatibility: Requires macOS or Linux, Python 3, and panopto-dl on PATH.
metadata:
  hermes:
    tags: [Education, Panopto, Downloads]
    requires_toolsets: [terminal]
---

# Panopto downloads

Use the bundled helper to inspect, plan, and synchronize recordings that the user's Panopto account is currently allowed to stream. The helper narrows the CLI surface and validates its quiet JSON response before anything reaches the conversation.

## Safe workflow

1. **Resolve the profile.** Before using the helper, run the read-only command
   `panopto-dl --json --quiet profile list`. If no profiles exist, ask the user
   to create one with `panopto-dl profile init`; do not guess a site, output path,
   or profile name. If exactly one profile exists, use its `name`. If several
   exist and the user has not already named one, ask which profile to use. Never
   substitute `nus` or the literal placeholder `PROFILE` automatically.

2. **Probe.** Run this before the first operation in a conversation:

   ```text
   python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE probe
   ```

   Continue only when the response has `status: "success"`. The probe is complete when a validated version envelope is returned.

3. **Check authentication.** Run `auth-status`. If it returns `AUTH_REQUIRED`, ask the user to open their desktop or RDP session and run `panopto-dl --profile PROFILE auth login` themselves. Resume only after `auth-status` succeeds. Keep passwords, MFA codes, cookies, and browser data outside chat.

4. **Discover or inspect.** Use the read-only helper operations below. A Canvas agent may first locate a Panopto Viewer, Embed, or folder URL, then pass only that URL to `inspect`. Canvas discovery remains a separate workflow with separate credentials.

5. **Plan a one-off download or backfill.** Run `plan`, summarize its exact session count, estimated bytes, policy, expiry, and plan ID from the validated result, then ask the user to approve that plan ID. Approval is complete only when the user explicitly accepts the displayed plan.

6. **Apply the approved plan.** After approval, run `apply PLAN_ID` as a background terminal process and poll it with Hermes process management. Treat any changed or expired plan as a new decision and return to step 5.

7. **Synchronize pre-approved sources.** Run `sync` without per-run approval only when the profile's registered sources already have automatic sync enabled. Run it in the background and poll it to completion.

Use the helper for agent-initiated Panopto operations. Source add/remove and interactive login are intentionally outside its command surface. Explain the required human command when either is needed.

## Helper operations

All commands return one validated schema `1.0` JSON object. Keep `--profile` before the operation.

```text
python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE auth-status
python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE discover-folders
python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE discover-sessions [--source ALIAS]
python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE source-list
python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE inspect URL_OR_ID
python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE status
python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE plan [--source ALIAS] [--target URL_OR_ID]
python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE plan --source ALIAS --backfill-all
python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE plan --source ALIAS --since YYYY-MM-DD
python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE plan --source ALIAS --last COUNT
python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE apply PLAN_ID
python3 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py --profile PROFILE sync
```

The helper accepts only its documented typed options. It has no raw argument or shell-command escape hatch.

## Results and recovery

- `success`: report the completed result and safe local paths.
- `partial`: report completed and failed counts, then identify the safe next action. Do not claim the batch succeeded.
- `AUTH_REQUIRED`: request desktop or RDP login outside chat.
- `DISK_FULL` or another disk guard: ask the user to free space or change their configured output root.
- `BUSY`: report that another mutating profile command is active; wait or retry only when requested.
- `INVALID_PLAN` or expiry: create and display a fresh plan.
- Other `error` results: report the symbolic code and sanitized message. Do not reconstruct or request hidden URLs, cookies, headers, or response bodies.

## Script-only scheduling

When the user explicitly asks for recurring sync, install both scripts into Hermes' permitted script directory and store the non-secret profile name in `panopto-sync.profile`:

Use the profile name resolved in step 1; do not guess one for scheduling.

```text
install -m 0700 ${HERMES_SKILL_DIR}/scripts/panopto_agent.py ~/.hermes/scripts/panopto_agent.py
install -m 0700 ${HERMES_SKILL_DIR}/scripts/panopto_cron.py ~/.hermes/scripts/panopto-sync.py
python3 ~/.hermes/scripts/panopto-sync.py --configure-profile PROFILE
```

Create a Hermes cron job for `panopto-sync.py` with `no_agent=true`. A successful tick emits nothing. Authentication, disk, partial, or terminal failures emit one sanitized action line. Scheduling is complete only after a manual test tick is silent on success or produces the expected safe alert on failure.
