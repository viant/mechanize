# LLM guide to Mechanize

Mechanize provides an authenticated MCP gateway for bounded macOS and Chrome
automation. The gateway exposes discovery, consent request/status, observation,
Endly sessions and runs, operation status/cancel, and durable run-state tools.
The connected host's capability map and policy are authoritative: a parser method
may exist while the configured backend does not support it. Mutation availability
depends on the current host's verified executor, enrollment, and consent.

Use this sequence: **discover → request permission → wait for human approval →
observe → validate → run → inspect execution and business status**. Never treat
validation, input dispatch, or Endly completion alone as proof that the requested
business outcome occurred.

## Discover tools and actual capabilities

Call `mechanize_capabilities` and `mechanize_describe` first. They return the
shared action definitions, capability map for the authenticated user, schema
version, and `businessReliability` (currently `unmeasured`). `mechanize_describe`
also returns `sourceFormats` and the strict `workflowSchema`. The names describe
the typed language; use only actions and surfaces marked supported by the
current host. `skill_list` and `skill_get` retrieve bundled
workflow guidance; a skill does not grant permissions.

Identity comes from the authenticated MCP context. Do not send a user ID,
namespace, or storage path to select authority. Open an owned session with
`mechanize_session_open`; use its `sessionId` for later session-scoped calls.

## Request and receive consent

A verified client submits a bounded request with
`mechanize_permission_request`, including its `sessionId`, exact `scope`,
requested `modes`, human-readable `purpose`, and `durationSeconds`. Valid scope
kinds are `application` (bundle ID), `window` (bundle and stable window ID),
and `origin` (exact HTTP(S) origin). Modes are `observe`, `control`, and
`record`. A successful request returns `permissionRequired`, a `requestID`, and
`dispatchState: notDispatched`; it is not approval and performs no action.

The verified human reviews, allows, or denies requests in the native permissions
console. The requesting MCP client cannot approve itself. Poll
`mechanize_permission_status` with the same `sessionId` and `requestID` to read
the request status and, after approval, the grant reference. Use that grant ID
and the same purpose/session on `mechanize_observe` or a run. Consent is bound
to the approved target, modes, purpose, client, session, and expiry. macOS TCC
permissions and backend capabilities remain separate requirements.

For web mutations, pass the existing approved `grantId` explicitly to
`mechanize_script_run`. The renderer admission binds that grant before durable
intent is committed. An omitted grant must not be interpreted as a new approval;
reuse an applicable existing grant or obtain one through the permission tools.

## Observe and choose a target

Call `mechanize_observe` with the exact surface plus the approved `sessionId`,
`grantId`, and `purpose`. A native surface uses `kind: native` and `bundleId`;
a browser surface uses `kind: web` and the enrolled `origin`. Observations are
bounded and time-sensitive. Check surface identity, sequence, truncation, and
unavailable fields. Prefer semantic roles, names, or identifiers and require
one match for an action. If the target is ambiguous, narrow scope or ask for
clarification rather than guessing.

Refs in observations are short-lived handles. Resolve the semantic locator
again after another snapshot or mutation, and do not persist refs across
sessions or restarts.

`getById` and `getByTestId` use exact matching when `exact` is omitted.
Explicit `exact: false` is preserved and remains unsupported on native routes
that require exact selectors. Identifier reuse still requires complete scoped
lookup and uniqueness checks.

### Scoped native lookup

When the current host advertises `native:menuBarScope` or
`native:focusedElementScope`, use the corresponding scope to avoid traversing
unrelated application content:

```text
let finder = app("com.apple.finder", processId: 661, processStartToken: "100:2")
finder.menuBar().getByRole("menuitem", name: "Go to Folder…", exact: true).click()
finder.focusedElement().getById("PathTextField").fill("/requested/folder")
```

The process values above are illustrative; obtain the current owned process
identity and inspect the actual control before using it. Each scope still needs
an explicit locator and a complete bounded subtree. It cannot be combined with
window/frame scopes or used for application open/activate operations. The helper
rechecks the selected app root before input; a changed focus is a failed action,
not permission to search another window. Missing capability or scope confirmation
must not fall back to a full-app lookup. Existing whole-app recovery contracts do
not yet qualify these scopes.

## Validate and run typed workflows

`mechanize_script_validate` compiles and type-checks source without execution.
Set `format` to `dsl` (the default), `json`, or `yaml`. JSON and YAML accept a
strict typed plan/workflow envelope. An envelope can declare typed inputs,
surfaces, an objective, constraints, requirements, checkpoints, and steps;
its `command` entries contain one DSL instruction each. Validation proves
syntax and typed-plan validity only. It does not grant consent, establish
backend support, or show that an action will run.

The shared DSL includes `click`, `fill`, `read`, `check`, `uncheck`, `select`,
`pressKey`, and bounded `expect` assertions, subject to the capability map and
backend implementation. For example:

```text
let caseApp = app("com.example.CaseDesk")
let title = caseApp.getById("case-title").read("text")
caseApp.getByLabel("Summary", exact: true).fill(title)
expect(caseApp.getByLabel("Summary", exact: true)).toHaveValue(title, timeout: 5s)
```

This is accepted grammar, not a claim that this host allows those mutations.
The host's `Policy` currently sets `AllowMutation: false`, so mutation plans
are rejected at the gateway. Do not try another tool or route to bypass that
policy. Read-only methods also require advertised capabilities and valid
consent.

Use `mechanize_step_run` for exactly one execution step or
`mechanize_script_run` for a compiled workflow. Both require `sessionId`, a
unique `clientRequestId`, and `source`; `format` is optional. Supply the grant
ID and purpose for consent-gated work. Do not transparently retry an uncertain
mutation: inspect current state and reconcile the possible effect first.

For an intended business workflow, declare its objective and any required
adapter in the typed envelope. The host must have an enrolled authoritative
completion oracle for that adapter and objective before it can verify business
success. No production business oracle is currently enrolled, so this host keeps
business completion `unverified`, even when Endly reports execution complete.
Fixture oracles demonstrate the separate verification path; they do not qualify
a production integration.

## Inspect execution, business outcome, and durable state

Run results and `mechanize_operation_status` report distinct
`executionStatus`, `businessStatus`, and `verificationState`. Execution status
says what Endly did. Business status says whether the declared objective was
independently established. Inspect `verificationReason`, `objective`, and any
structured error's `dispatchState` and `effectState`; retain available evidence
references. A pending, unknown, unavailable, or unverified result is not
success. `mechanize_operation_cancel` requests cancellation, but already-dispatched
effects still need reconciliation.

When advertised, `mechanize_state_get` reads an owned durable run by `runId`,
including variables, revision, progress, checkpoints, and unresolved effects.
`mechanize_state_pause` requests a guarded pause at a safe boundary using
`expectedRevision`. `mechanize_state_patch` changes permitted typed variables
only in a safely paused or new run and requires the expected revision. A host
guard freezes admission through the durable commit and refresh of live runtime
bindings. Bindings consumed directly or transitively by confirmed effects
cannot be changed; the patch does not alter objectives, history, or the effect
ledger. If the post-commit projection or runtime refresh fails, the committed
state is returned with transient `needsAttention`; the database is not rolled
back and its run status is not changed. Reconcile runtime state before
continuing. State tools do not resolve an uncertain external effect.

When advertised, `mechanize_state_resume` admits a stopped run into an already
owned and human-approved session. Supply `sessionId`, `runId`, `grantId`,
`purpose`, and the current state's `expectedRevision`, `expectedPlanId` and
`expectedObjectiveId`. State get exposes `revision`, `planId`, `objectiveId`
and any durable `sessionId`/`operationId` correlation. Old grants are not moved
to new sessions. Resume requires a held desktop fence and known effects; the
current bootstrap host has no mutation fence and therefore cannot admit live
resume. Confirmed effects are skipped and remaining targets use normal fresh
backend resolution. A lost acknowledgement requires correlation/status inspection
before retrying, not guessing the next revision or repeating UI actions.

Close the owned session with
`mechanize_session_close` when finished.

## Capture native window evidence

The gateway registers `mechanize_capture_windows` when bounded helper
discovery is configured and `mechanize_capture` when capture, encrypted artifact
storage, and durable publication are configured. Capability flags describe
configured transports and publication; they do not mean Screen Recording TCC
approval or human consent is present. Capture is limited to an enrolled native
application and an exact positive PID and physical window ID. Chrome and whole
display capture are not supported by these tools.

For discovery, request `observe` consent for the exact native application and
then call `mechanize_capture_windows` with the same session, grant, purpose,
surface, and a limit from 1 through 128. Discovery is bounded and validates
fresh physical identities. A once grant is consumed by discovery, so use a
session grant when discovery will be followed by capture. Returned window
identities are observations and do not themselves authorize capture. Refresh
discovery if the target changes.

Call `mechanize_capture` with the exact surface, PID, window ID, and matching
consent fields. The one observe grant is retained through helper cleanup,
encrypted byte storage, and Datly metadata publication. Successful responses
include the encrypted artifact reference and verified capture metadata. PNGs up
to 2 MiB are also returned as MCP image content; larger PNGs remain saved in full
and may return a bounded PNG/JPEG display preview. Check `imageIsPreview` and
`preview` dimensions/bounds/logical scale mapping; the artifact hash still belongs
to the original. If preview limits cannot be met, `imageReturned` is false with
a reason. Screenshot evidence is separate
from accessibility observations and does not prove a business outcome.

On helper cleanup uncertainty, do not retry until cleanup has been reconciled.
If metadata publication acknowledgement is unknown, the encrypted artifact
reference is retained and metadata/checkpoint reachability must be reconciled;
the bytes are not rolled back. These code paths and fixture tests do not qualify
signed installation, live Screen Recording/TCC behavior, deployed helper
cleanup, publication recovery, or production reliability.

## Reuse a parameterized scenario

When advertised, `mechanize_scenario_publish` stores an immutable draft with a
typed plan, input schema, symbolic entity key, objective and recording provenance.
It rejects captured action values/defaults/live handles. Publication reports the
exact revision/hash and any explicit normalization; caller review claims never
establish verified provenance or qualification.

`mechanize_scenario_list` returns compact owned summaries with bounded keyset
pages and objective/exact revision filters. `mechanize_scenario_select` takes the
requested objective hash, entity, typed schema/inputs and surface. It checks
trusted current environment, all mixed-plan surface ceilings, reverified
provenance and exact cohort qualification. Request fields cannot supply those
authorities. The packaged host currently has no trusted environment/qualification
provider, so selection returns `needsAttention` and executes nothing.

A qualified selection remains `proposalOnly`. Inspect its immutable revision and
typed plan, obtain appropriate consent, then explicitly run it through Endly.
Never relax a missing capability, entity, verification contract or unknown-effect
barrier to manufacture a match. Recovery planner transport and persisted repair
revision execution remain separate integration work.

## Repair a changed situation

`mechanize_recovery_context` inspects the exact owned stopped run/plan/revision.
The server supplies a bounded redacted view from fresh trusted observations,
contracts and original effect history; the caller cannot manufacture this
authority. Unknown effects, an untracked read-only prefix or unavailable
evidence returns `needsAttention`.

`mechanize_recovery_admit` accepts a strict patch, preserves every objective,
input and completed business effect, and CAS-publishes immutable revision,
original-ledger lineage, provenance, budgets and audit before resume. It starts
no workflow. Require `commitConfirmed` and `readyToResume`; then explicitly
resume under appropriate current consent. Uncertain acknowledgements retain
the exact repair reference until scoped reconciliation establishes the commit.
The packaged host currently supplies no trusted evidence/runtime-ready bindings,
so recovery admission remains attention-gated. Disposable fixture evidence does
not qualify a production repair cohort.

## Current limits and useful error handling

If a call fails, preserve its structured error code, stage, dispatch/effect
state, and evidence. Refresh the scoped observation and check target identity,
permissions, capabilities, and locator cardinality. Stop when the requested
capability or permission is unavailable. If a mutation may have dispatched,
reconcile before considering another attempt; never turn an unknown effect or
incomplete observation into success.

Native and Chrome code paths, fixtures, and consent enforcement exist, but this
does not qualify signed installation, live macOS helper/TCC behavior, real
Chrome enrollment, held-input cleanup, production business outcomes, or broad
platform support. Treat release qualifications and reliability as open until
the host reports and independently demonstrates them.

### Native window position

When the host advertises `native:windowPosition`, a pinned native window can be
moved using an exact locator and a typed position:

```text
finder.getByRole("window", name: "mechanize", exact: true).moveTo({"x":100,"y":100})
```

Pin `finder` to a freshly discovered process ID and start token. Coordinates are
integer global logical points in the range -32768 through 32767; quote the object
keys. This operation uses a complete flat window list, not a full application
snapshot. It requires an actual AXWindow with a settable position and existing
control authority. It performs one setter call, never a drag or focus fallback.
An exact fresh position readback verifies the UI move; unavailable or mismatched
readback remains unknown and must not be blindly retried. Window/frame/ancestor
and native-root scopes cannot be mixed into this window-root operation.
