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

1. **Discover.** Call `mechanize_capabilities` once. Read `mechanize_describe`
   when additional syntax or workflow schema is needed; avoid duplicate full
   discovery on each action. Treat
   their live capability map, method descriptions and policy as authoritative;
   do not infer support from a method name or an example. Observed node
   `actions` and `valueSettable` metadata guide target choice but are not
   permission grants or proof that a qualified method/runtime can perform an
   action. `businessReliability` may be `unmeasured`.
2. **Authorize.** Open an owned session with `mechanize_session_open` and use
   the exact business purpose on observe/run calls. A matching permanent grant
   for this verified client, target, mode and purpose is resolved by the host
   from session and purpose; omit `grantId` when the tool permits it. Do not
   prompt again just because no grant ID was returned. Controllers admitted by saved
   trusted-origin policy receive bounded operation authorization automatically
   within the allowed apps/sites; do not request a second Mechanize approval. If the server reports
   `permissionRequired` and permission tools are advertised, request access for
   the exact scope, modes and bounded duration, then inspect status with the
   returned `requestID`. The employee decides in the native panel; the
   requesting agent cannot grant itself access. Do not repeatedly resubmit
   denied requests. macOS system permissions and operator ceilings are separate
   requirements.
3. **Observe.** Call `mechanize_observe` for a granted `native` bundle ID or
   `web` origin. Treat observations as bounded and time-sensitive. Check
   `truncated`, `unavailable`, and the surface identity before relying on them. Visible controls
   are prioritized within the bounded snapshot; truncation still means the
   observation is incomplete. Do not assume Chrome DOM roles match Playwright’s
   computed accessibility roles—validate the current Mechanize locator.
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
   establish broad native coverage. Check `mechanize_browser_status` for Chrome:
   a connected native port alone does not prove process, scope, executor or
   inventory qualification. Use the live flags and attention code, not a skill's
   historical enrollment description, to decide whether Web actions are ready.
6. **Verify.** Poll `mechanize_operation_status` with the returned
   `sessionId` and `operationId`. Execution completion is separate from
   business verification. Check `businessStatus`, `verificationState`, objective
   evidence and `verificationReason`. Only a qualified authoritative outcome
   receipt can establish business success. A native focus or navigation proof
   establishes that UI step, not the user's business outcome. Inspect the live
   adapter enrollment; unavailable evidence stays unverified. Close an owned
   session with `mechanize_session_close` when done.

## Choose a website or native application

A website displayed in Chrome is a `web` surface, even when its product name
sounds like a desktop app. Never derive a native bundle ID from a website name
or hostname. When capabilities include `controllerContext`, it identifies the
verified web origin hosting this connection; use it only when the requested
target is that page. For MCP website observation, use
`surface: {kind: "web", origin: "<exact verified origin>"}`; the DSL uses
`web.tab`. Follow the advertised schema for each tool rather than copying
connection metadata as its arguments.
Obtain its fresh opaque tab handle with
`mechanize_browser_tabs`. For another website, use its independently known
origin. Connection metadata does not grant tool access.

For native interaction, establish the actual installed application identity
from advertised discovery or user-provided identity, then confirm its process
and window with `mechanize_capture_windows`. Do not invent a bundle ID to
request permission. Native visual fallback for a Chrome page targets the
verified Chrome application/window, not a guessed app named after the site.

## Observation surfaces and permission scopes

These are different JSON contracts; do not copy `surface` into `scope`.

- Website observation/tab discovery: `surface: {kind: "web", origin: "https://example.test"}`. Add the discovered opaque `tabId` for document operations; tab discovery itself takes only the exact origin.
- Native observation/capture: `surface: {kind: "native", bundleId: "<discovered bundle ID>"}` plus the required current process/window identity. Capture tools currently require a native surface; for a website screenshot discover its actual Chrome window.
- Website permission request: `scope: {kind: "origin", origin: "https://example.test"}`, with `modes: ["observe"]` for reads or `["observe", "control"]` when both are needed.
- Native permission request: `scope: {kind: "application", bundleID: "<discovered bundle ID>"}`; an exact window scope additionally uses `kind: "window"` and `windowID`.

Permission requests also require the owned `sessionId`, consistent `purpose`,
and bounded `durationSeconds`. Notice `bundleId` on surfaces versus `bundleID`
on consent scopes. `displayName` is optional presentation, never authority.
Request permission only after `permissionRequired`; `invalidArguments`,
`invalidSurface`, `invalidScopeKind`, `invalidConsentScope`, or `unsupportedMode`
require correcting that request, not broader access. `sessionNotOwned` requires
using this connection's owned session. A generic inventory failure does not
prove missing consent; retain the original failure and inspect its closed code.

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

## Short Chrome action loops

Use a qualified exact tab handle and exact unique semantic locators. In JSON,
set `locator.exact: true` explicitly and declare `requires.adapters: [web]`.
Start with a three-second mutation timeout; native messaging and cold debugger
attachment share that budget. Do not add a separate long sleep after a click.
Inspect the declared postcondition or fresh state to decide the next action.

The CDP pointer path activates only the admitted tab and revalidates its document
before measuring the hit target. It shares the declared action deadline, capped
at three seconds. Activation does not prove that the subsequent click ran.

Status refresh can query retained original v2 receipts without replaying input.
A matching signed fingerprint can resolve transport uncertainty; it does not
confirm a durable effect or business objective.
A machine-only cleanup block retains an already approved observation mode, so
you can inspect fresh state while control remains suspended. Human revocation
and Vault credential/secure-entry protection still deny exposure. Never turn an unknown result into
a new click just because the page appears unchanged. Inspect the original receipt
and use the enrolled recovery contract. An error after executor return may mean
input was already sent; distinguish this from an explicit `notDispatched` result.

For Playwright routing, exact/indexed locator grammar, workflow deadlines and
public value postconditions, read [references/chrome-actions.md](references/chrome-actions.md).

For the target-oriented JavaScript Computer API adapter, read
[../../sdk/computer/README.md](../../sdk/computer/README.md). Select an exact
owned app or tab, observe state, act with an explicit business key and deadline,
then refresh state. This initial adapter does not imply support for every Codex
Computer Use method. Never use its public fill or keyboard methods for secrets.

## Native postconditions

Pin native predicates to the same exact app process and window as the action.
Include `windowTitle` (and `windowRole` where needed) in the predicate inputs;
an unscoped app-wide AX traversal can exceed a short verification deadline.
For enabled, focused or checked state, use `native.valueEquals` with the exact
semantic locator and expected boolean.

For a public text fill, use `native.literalValueMatches` with `attribute: value`
and the original public literal as `expected`. This requires control consent
but compares locally and returns only a boolean; it does not extract the field
value. Do not use this predicate to probe credentials or other secret values.
A dispatched Enter or fill does not establish its business postcondition. If
verification fails, preserve the original outcome and inspect fresh state;
never repeat the input merely to obtain a passing postcondition.

## Large native menu bars

When whole-menu observation is truncated, use the advertised `native:menuScope`
capability to select one observed top-level menu name. Supply `nativeRoot:
"menuBar"` and `nativeMenu: "File"` to `mechanize_observe`, with the exact native
PID/birth surface. The result reports that same menu scope and covers only its
subtree; it does not claim whole-application completeness.

The matching DSL is `app("com.example.Editor", processId: 42,
processStartToken: "100:1").menuBar(name: "File")`, followed by a fresh unique
observed locator. Use actual discovered process identity and menu names. A
JSON selector uses `scope: {nativeRoot: "menuBar", nativeMenu: "File"}`. Native
postcondition inputs accept the same `nativeRoot`/`nativeMenu` pair. Duplicate
or unavailable top menus remain a refusal; do not use an index to bypass it.

## Foreground activation confirmation

Source `app.activate` submits one activation request, then observes the exact
foreground PID, login UID, kernel birth token and bundle through the qualified
foreground reader for at most one second, bounded by the request deadline.
Acceptance of the activation request alone is not confirmation. An unconfirmed
activation remains `unknown`; never replay it as a focus repair. A confirmed
helper reply carries `foregroundConfirmed`, and the backend also independently
checks the exact app's active identity. This confirms a sampled app foreground,
not a particular window, focused control, or lasting keyboard authority: each
later input must revalidate its own target and foreground gates. Source tests
establish the contract; installed runtime qualification remains separate.

## Private website sign-in

Use `mechanize_browser_tabs` to obtain an opaque handle for the requested exact
origin. Use `mechanize_credential_prepare`, then `mechanize_credential_status`
to qualify the form privately before `mechanize_credential_apply`. The host
uses existing reusable control consent and privately selects one saved Basic
record whose endpoint matches the exact HTTPS origin. It does not require a
separate per-use Vault approval. `needsConfiguration` means the native Vault
needs an unambiguous matching record; do not ask for credentials in chat.

Never pass usernames, passwords, record contents or a caller-selected record ID
to these tools. Credential protection applies to the exact protected web DOM;
it is not a desktop-wide observation prohibition. Authorized native screenshots
and metadata retain their normal consent checks. Use masked visual state for
layout or navigation when needed, but never reveal a password or use DOM reads
or public input methods to bypass the private credential flow. Follow the
returned state before submitting through
`mechanize_credential_submit`; unknown attempts must never be replayed. A bank's
MFA or other real challenge can still require local user action. Credential
submission is not evidence of successful sign-in or a completed payment.

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
