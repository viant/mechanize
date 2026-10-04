---
name: mechanize-recording
description: Guide an explicitly requested macOS or Chrome demonstration recording into a redacted, gap-aware, parameterized reusable script. Use only when the user asks to record or review a recording; ordinary one-step automation and script reuse do not need this skill.
---

# Mechanize demonstration recording

First choose the right mode: reuse a qualified existing scenario if available;
use `mechanize_step_run` for an authorized, one-off action; record only when the
user explicitly asks to capture a demonstration for reuse. Recording is visible,
scoped collection of work data. Do not start it implicitly, broaden its app/tab
scope, or use covert capture if recording is unsupported or denied.

## Check capability before capture

Call `mechanize_capabilities` and inspect the advertised surface and recording
support and discover the actual tool schemas. Backend APIs are not evidence of
an available MCP tool. Recording tools are registered only when the host wires
the recording service; native and Chrome availability depend on the configured
backend and current permissions. Use the discovered `mechanize_record_start`,
`mechanize_record_pause`, `mechanize_record_stop`, `mechanize_record_status` and
`mechanize_record_export` contracts. If the server does not advertise an
authorized recording path for the requested surface, report that limitation
and offer to draft a script from user-provided steps.

Before capture, establish the user's explicit consent,
target desktop or app/profile/tab and origins, bounded duration/event scope, objective,
business key(s), expected outcome evidence, and retention/export intent. Show
when capture is active and make pause/stop easy. Capture only the declared
surface.

For a requested demonstration across app switches, discover whether the server
accepts the exact desktop surface `{ "kind": "desktop" }` and a `record` grant.
Do not add application/origin/tab fields to a desktop scope or silently replace
an application-only approval with desktop access. OS Accessibility permission
and an observe/control grant do not themselves authorize recording.

## Protect data and preserve evidence quality

- Never collect passwords, tokens, secret fields, or credential values. Do not
  infer that a value is safe because the UI did not mark it sensitive. Redact
  locally before persistence/export; if safe redaction cannot be established,
  pause or stop and report why.
- Keep event volume and retained artifacts bounded. Preserve app/tab/profile
  identity, timestamps, locator provenance, source, and ordering. Surface
  truncation and every event gap. Do not fill gaps with guessed actions or
  present incomplete coverage as a complete demonstration.
- Ask for the business objective and an independent way to verify it. Keep
  business keys explicit and scoped to the run. Parameterize task-specific
  values; use protected references for secrets, never captured secret text.
- Export an editable semantic script with unresolved targets, unsupported
  steps, confidence/provenance, and parameters visible for review. A recording
  replays intent only after validation; replaying input does not prove success.
- Preserve native UID, bundle, process start token and window identity when
  present. A public macOS event-tap source does not establish that input came
  from a human; keep unattested events and withheld/hashed targets marked for
  review. An application activation event does not prove an app-open action.

## Validate reuse

Run syntax/policy validation and review all effects and required capabilities.
Replay only in an isolated disposable fixture or other user-authorized test
workspace, with independent outcome verification. Do not qualify a script by
replaying it against the employee's live work. If no safe isolated replay and
outcome check are available, label the export unqualified and state the gap.

If a recording is interrupted, redaction fails, scope changes, or events are
lost, stop the recording and preserve the gap in its evidence. Never switch to
screen-wide or background collection as a workaround.
