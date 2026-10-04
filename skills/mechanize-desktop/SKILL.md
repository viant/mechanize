---
name: mechanize-desktop
description: Use Mechanize MCP to inspect authorized macOS apps or Chrome tabs, validate semantic locators, run typed steps/scripts, and reconcile uncertain effects. Use only when a Mechanize MCP server is connected; ordinary browser or desktop questions do not need this skill.
---

# Mechanize desktop and browser automation

Use the connected Mechanize MCP server only for surfaces and actions it
advertises for the authenticated user. MCP capability is not a permission
grant. Never imply that access, a mutation, or business success is available
until the server reports the relevant authorization and the result is verified.

## Workflow

1. **Discover.** Call `mechanize_capabilities` and `mechanize_describe`. Treat
   their live capability map, method descriptions and policy as authoritative;
   do not infer support from a method name or an example. Observed node
   `actions` and `valueSettable` metadata guide target choice but are not
   permission grants or proof that a qualified method/runtime can perform an
   action. `businessReliability` may be `unmeasured`.
2. **Authorize.** Open an owned session with `mechanize_session_open` and use
   the exact business purpose on observe/run calls. A matching permanent grant
   for this verified client, target, mode and purpose is resolved by the host
   from session and purpose; omit `grantId` when the tool permits it. Do not
   prompt again just because no grant ID was returned. If the server reports
   `permissionRequired` and permission tools are advertised, request access for
   the exact scope, modes and bounded duration, then inspect status with the
   returned `requestID`. The employee decides in the native panel; the
   requesting agent cannot grant itself access. Do not repeatedly resubmit
   denied requests. macOS system permissions and operator ceilings are separate
   requirements.
3. **Observe.** Call `mechanize_observe` for a granted `native` bundle ID or
   `web` origin. Treat observations as bounded and time-sensitive. Check
   `truncated`, `unavailable`, and the surface identity before relying on them.
4. **Find and validate.** Choose a semantic locator in the observed app/window
   or tab. Require one match for an action; clarify ambiguity by narrowing the
   scope or locator. Use `mechanize_script_validate` to parse/type-check DSL
   without executing it. This check is not an authorization grant and does not
   prove a backend will execute the plan.
5. **Run.** Keep the owned `sessionId` for subsequent calls.
   Use `mechanize_step_run` for exactly one
   execution step or `mechanize_script_run` for a validated script. Supply a
   unique `clientRequestId` for each intended run. Native runtime paths may
   support advertised mutations when live policy, consent, system permissions,
   operator ceilings and backend qualification allow them; this does not
   establish broad native coverage. Chrome is currently unenrolled, so parsed
   or advertised Web actions do not mean its runtime is ready for execution.
6. **Verify.** Poll `mechanize_operation_status` with the returned
   `sessionId` and `operationId`. Execution completion is separate from
   business verification. Check `businessStatus`, `verificationState`, objective
   evidence and `verificationReason`. Only a qualified authoritative outcome
   receipt can establish business success. No production outcome adapter is
   currently enrolled in the packaged host; unavailable evidence stays
   unverified. Close an owned session with `mechanize_session_close` when done.

## Supported DSL forms

Validation and run tools accept `format: dsl` (the default), `json`, or `yaml`.
Use a strict JSON/YAML workflow envelope to declare typed inputs, surfaces,
postconditions and a business objective through an enrolled read-only adapter.
The format is explicit; never send JavaScript or shell as an alternate format.
For the closed envelope grammar, inspect the server's advertised schema and
validate before execution. Adapter names in a plan do not enroll or qualify them.

The current parser/compiler accepts shared macOS and Chrome scopes, semantic
locators, reads, fills, clicks, and bounded assertions. Validate any proposed
syntax with `mechanize_script_validate`; do not add host-language code, shell
commands, or guessed methods.

```text
let caseApp = app("com.example.CaseDesk")
let crm = web.tab(origin: "https://crm.example.test", title: "Cases")
let summary = caseApp.getById("case-summary").read("value")
crm.getByLabel("Summary", exact: true).fill(summary)
expect(crm.getByLabel("Summary", exact: true)).toHaveValue(summary, timeout: 5s)
caseApp.getByRole("button", name: "Export", exact: true).click()
```

This bare DSL snippet illustrates grammar only; it is not an executable recipe
for the packaged durable host. Mutating DSL steps default to
`externalNonIdempotent`, and durable execution requires each such step to carry
an exact typed `effect.businessKey` in a JSON/YAML workflow envelope. The
Calculator example at `examples/endly/calculator.yaml` shows the supported
shape. A semantic press without a verified effect postcondition may dispatch
but remains `unknown`, which blocks replay until reconciled; add a suitable
postcondition when the action has an independently observable result. The
grammar rejects unknown methods/options and arbitrary JavaScript or shell.
Locator strategies, assertion observations, and actions can still be missing
for a particular surface. Check `mechanize_capabilities` and validation.
Prefer stable bundle ID/origin plus semantic locator details in saved scripts.

## References and transient targets

For visual evidence, use `mechanize_capture_windows` and `mechanize_capture`
when advertised. They require the owned session, approved observe grant and
exact purpose. Discovery is limited to one native bundle and returns physical
PID/window IDs, process start tokens, bounded titles and explicit truncation.
For a multi-process native app, narrow the surface with the paired `processId`
and `processStartToken` from a fresh discovery row; never use either alone or
treat the pair as lasting authority. The helper rechecks exact application
ownership.

A once grant used for discovery is consumed. Use a bounded session grant for
discovery followed by capture, or obtain a separate once grant for the capture.
One capture grant covers capture, helper cleanup, encrypted bytes and Datly
publication. Check cleanup/publication uncertainty before another attempt.
The tool returns the original PNG up to its inline byte limit. Larger images
remain saved in full and may return an explicitly labelled PNG/JPEG preview:
check `imageIsPreview`, `preview`, its dimensions and logical `scaleX`/`scaleY`
mapping. A preview is a display derivative, never original pixel evidence. If
safe preview limits cannot be met, `imageReturned` is false with a reason.
An artifact reference is not a bearer credential. Screenshot and AX state are
separate observations, and a screenshot never proves business completion.

`native:captureWindowTransport`, `native:captureDiscoveryTransport` and
`native:encryptedCapturePublication` report configured paths, not human grants,
macOS Screen Recording permission, signing or live qualification. Permission
errors require the employee to review helper status in the native panel. Chrome
page-image and whole-display capture are currently unsupported.

Element refs in observations are short-lived execution handles. On the native
helper they are invalidated by a new snapshot or mutation and expire after
five seconds. Do not persist or reuse them across observations, sessions, or
restarts; resolve the locator again from fresh state. Persist app/window/tab
identity and a semantic locator instead.

## Dedicated state tools

Use `mechanize_state_get` with the returned `runId` to inspect owned durable
variables, revision, progress, checkpoints and unresolved effects. Use
`mechanize_state_patch` only when advertised and the server confirms a safe
new/paused context; provide `expectedRevision` and typed variables. It cannot
clear effects or change objectives/history. A rejected patch is not permission
to edit database files or retry with a guessed revision.

A `stateCommittedNeedsAttention` error means the durable patch committed but
live Endly bindings did not refresh. Keep its confirmed revision/state, inspect
the stopped run, and resolve the runtime issue before proceeding. Do not assume
rollback or repeat the same patch. `needsAttention` here is transient refresh
metadata, not a separately persisted run status. Confirmed effect dependencies,
including transitive aliases, cannot be changed by a state patch.

When `mechanize_state_resume` is advertised, first inspect the current `runId`,
`revision`, `planId`, `objectiveId` and unresolved effects with state get. Open
an owned session, request appropriate human consent for it, and supply that
session's approved `grantId` and exact `purpose` to resume, with
`expectedRevision`, `expectedPlanId` and `expectedObjectiveId` copied from the
current durable state. Resume uses that session; it never transfers old grants.
Unknown effects, terminal state, a stale revision or missing desktop fence block
admission. Confirmed effects are skipped; remaining targets are resolved again
through the normal backend checks. If a resume reply is lost, inspect durable
`sessionId`/`operationId` correlation and status before considering another call.
Never guess identity/revision values or clear an uncertainty barrier to continue.

When recovery tools are advertised, `mechanize_recovery_context` takes the
exact owned run/plan/revision and returns only bounded redacted planner context
from trusted fresh evidence. Missing authority or untracked/unknown effects
returns `needsAttention`. Submit a strict objective-preserving patch through
`mechanize_recovery_admit`; the server rechecks context, preserves original
effects, and atomically reserves finite budgets with immutable revision/lineage.
It does not execute. Only `commitConfirmed` plus `readyToResume` permits an
explicit consent-bound state resume. A lost admission reply requires exact
reference reconciliation; never guess a new revision or repeat an effect.
The packaged host currently has no trusted recovery evidence/runtime bindings,
so it stays attention-gated. A fixture repair result is not production qualification.

## Errors and uncertain effects

Read structured errors for `code`, `stage`, `dispatchState`, and `effectState`.
When a read fails, refresh the scoped observation and correct scope, locator,
capability, or permission problems before continuing. A zero-match or
multi-match result is not permission to guess. When a mutation may have been
dispatched, stop and reconcile its effect before considering another attempt.
Never transparently retry a mutation, and never convert `unknown`, incomplete
observation, or `unverified` into success. If the effect cannot be established,
report the uncertainty and the evidence available.

If execution is rejected by live policy, report that limit; do not attempt
another route to control the surface. Do not claim universal macOS or Chrome
coverage, permissions, reliability, recording, checkpointing, or recovery.

For connection and cross-host discovery, read [references/connection.md](references/connection.md).

For native file-dialog navigation and uncertain confirmation outcomes, read
[references/native-file-dialogs.md](references/native-file-dialogs.md) before
choosing a route. Its Chrome/macOS observations are qualification evidence for
that fixture, not guarantees for other apps or dialog implementations.
