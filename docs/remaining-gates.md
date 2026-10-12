# Remaining integration and qualification gates

This inventory describes the checked-in source and fixture coverage. An
implemented code path does not qualify signed installation, live macOS or Chrome
control, process-death recovery, or production reliability. See the
[qualification audit](qualification-audit.md) for the release checklist and the
[README](../README.md) for the supported architecture. Historical planning and
implementation-tracker files are not included in this repository; current status
must be checked against the source and reproducible test results linked here.

## Priority gates

| Priority / status | Gate and current implementation | Remaining qualification |
| --- | --- | --- |
| P0 — implemented paths; qualification open | **Consent through dispatch and cleanup.** The host composes the Datly-backed consent broker and optional native console. Mutations route through native or web control managers; grants bind the authenticated client, session, scope and purpose. Managers implement stop/retirement and uncertain-cleanup handling. See [host dispatch](../host/host.go), [native control](../host/native_control.go), [web control](../host/web_control.go), and [consent integration](../host/consent.go). | Exercise the signed installed console and helper with provisioned credentials. Demonstrate revoke during input, held-input cleanup, lost receipts, database failure and restart reconciliation. Inspect read-only dispatch lease handling separately from manager-owned mutation cleanup. Fixture cleanup does not prove live helper behavior. |
| P0 — missing live qualification | **Signed helper and macOS TCC.** Native observation, semantic control, capture, process identity and supervisor fencing have implementations and fixtures. Readiness is checked at runtime; this document does not report the permissions of an installed helper. See [native helper](../native/macos/README.md), [native backend](../backend/darwin/README.md), and [supervisor](../session/README.md). | Sign/notarize, install and upgrade the actual package. Prove helper-specific Accessibility, Screen Recording and applicable input permissions across restart, locked and disconnected sessions, with independently verified disposable-fixture outcomes. |
| P0 — implemented transport; qualification open | **Window capture and encrypted evidence.** Exact-window capture, discovery, bounded inline previews and encrypted artifact publication are wired through consent. See [capture transport](../backend/darwin/capture.md), [host capture](../host/capture.go), and [artifacts](../artifact/README.md). | Qualify installed-helper TCC attribution, revocation, cleanup uncertainty, metadata acknowledgement loss and orphan artifact handling. Transport capability does not establish permission or universal capture support. |
| P0 — missing live qualification | **Chrome enrollment and semantics.** The extension, native host, broker, scoped control leases, receipts and retirement paths have implementations and fixtures. See [Chrome backend](../backend/chrome/README.md) and [extension](../extension/chrome/README.md). | Use disposable real profiles and supported Chrome versions to qualify signed enrollment, native dialog handoff, navigation, permission changes, suspension, stale receipts and reconnect. |
| P0 — partial | **Independent business completion.** The DSL, Endly execution and durable effect ledger are connected. Execution and business verification are reported separately. See [durable execution](../engine/durable/execute.go), [objective completion](../engine/durable/objective.go), and [MCP status](../mcp/server.go). | Enroll authoritative per-adapter outcome providers and qualify exact entity/key matching, false-success rejection and unknown outcomes on supported application cohorts. |
| P1 — partial | **Recording, export and replay.** The host wires recording when Chrome or a native recording backend is configured, using durable append/read callbacks. See [host composition](../host/host.go), [native recording](../host/native_recording.go), and [durable recording](../engine/durable/recording.go). | Qualify sensitive-field redaction, gaps, retention, stop uncertainty, durable export and changed-input/layout replay with independent outcome verification. |
| P1 — partial | **Crash recovery and state synchronization.** Guarded state patch/refresh, checkpoints, initial/resumed operation correlation, unknown-effect barriers and confirmed-prefix reuse are implemented. See [state](../engine/durable/state.go), [resume](../engine/durable/resume.go), and [shutdown tests](../host/shutdown_test.go). | Inject actual broker/helper/Endly process death at commit and dispatch boundaries; prove task/session reconstruction, grants, partial restore reporting and pause/patch/resume behavior. Builder reconstruction fixtures are narrower than process-death recovery. |
| P1 — implemented bounded recovery; qualification open | **Scenario selection and repair admission.** Generated repair admission, immutable revisions, budget/CAS checks and original-ledger lineage are connected to Endly resume. See [lineage integration fixture](../engine/durable/lineage_test.go), [retry tests](../engine/durable/execute_retry_test.go), and [native recovery flow](../host/native_recovery_flow_test.go). | Enroll trusted environment, provenance, cohort and recovery-evidence providers. Qualify read-only prefix proof, held-out perturbations, wrong repairs and unknown effects. Optional source wiring does not establish installed recovery authority. |
| P1 — partial | **MCP and Scy acceptance.** Authenticated MCP, strict principal identity, bundled skills and disposable Endly/Datly acceptance cases exist. See [authentication](../auth/verifier.go), [MCP](../mcp/server.go), and [e2e coverage](../e2e/README.md). | Qualify packaged stdio/HTTP enrollment, expiry/rotation/reconnect and the full negative-claim and cross-user object/resource matrix. |
| P1 — missing release qualification | **Deployment and upgrades.** Development packaging and enrollment tooling exist. See [local installation](local-installation.md) and [developer mode](developer-mode.md). | Demonstrate reproducible clean-machine signed installation, source/resource packaging, upgrade/rollback, version skew and operator runbooks. An ad-hoc development build is not release-signing evidence. |
| P1 — missing measurements | **Reliability and operational stability.** Bounded queues/storage, fences, stop handling and scenario qualification contracts exist. See [scenario selection](../scenario/README.md) and the [qualification audit](qualification-audit.md). | Publish raw cohort trials, confidence bounds, exclusions, false-success/duplicate-effect counts and soak/contention/storage/key-outage results before claiming production reliability. |

## Current integration boundaries

The native helper has source-only, opt-in AX hierarchy invalidation
(`--allow-ax-observer-invalidation`). Callbacks carry a revision counter rather
than UI values. Focus/window notifications retire cached references; changes
during traversal reject the snapshot, and changes during a mutation request
reject dispatch before its ledger reservation. Existing ownership, scope,
process-birth and input checks remain required. Unsupported notifications and
changes without notifications still require fresh validation; observers are not
a complete change feed. Registration is bounded by AX messaging timeouts and
shutdown retires callbacks before source removal on the owning run-loop thread.
This route is not enabled in the installed runtime or enrolled through host
configuration yet. Live Office notification delivery, replacement and shutdown
qualification remain open. Typed role/focus readers distinguish absent data from
failed or malformed AX reads; other attribute readers have not all migrated.

[Host.New](../host/host.go) calls
[launchHostOptions](../host/native_launch_config.go), which can build trusted
native control providers from `NativeLaunch` enrollment, including semantic mode
and explicitly configured keyboard/frame capabilities. Without that enrollment,
this path supplies no native control options. `Host.NewWithOptions` also accepts
trusted injected providers. Both paths remain subject to helper identity,
readiness, physical-fence, policy and consent checks. Source integration alone
does not establish that a particular installed binary can mutate the desktop.

Native control is integrated into the host. Native stop and consent metadata
persistence have independent bounded budgets; uncertain cleanup retains authority
barriers. [Host.Close](../host/host.go) invokes Endly runtime shutdown before
closing durable storage and preserves storage when runtime shutdown cannot be
confirmed. Qualify these boundaries under real process failure and load; passing
fixtures do not establish production handshake or cancellation latency.

## Evidence maintenance

- Keep source status separate from installed-platform qualification. Record the
  command, revision, platform, outcome and exercised scope for each test run.
- The [regeneration script](../data/scripts/regenerate.sh) includes the generated
  reconciliation and stop-boundary components. Compare its inventory with
  `data/source/` whenever adding a use case, and validate regeneration against
  the pinned Datly executable and an infrastructure-provisioned discovery schema.
- Use the [e2e README](../e2e/README.md) for the bounded acceptance-case matrix;
  its recorded fixture results do not cover live desktop or process-death tests.
- Keep this inventory and the [qualification audit](qualification-audit.md)
  aligned with source changes. Do not infer completion percentages, universal
  application support or reliability probabilities from fixture pass counts.

## Native outcome admission correction (October 5, 2026)

An edited-copy Word Open Recent action was menuBar-scoped but declared a separate
window-root text comparison. Dispatch did not produce the expected window and
late reconciliation rejected the boundary transition. The original unknown
effect remains stopped and preserved. The edited-copy reopen is not qualified.

New source applies the enrolled native recovery contract's process, root, window,
ancestor and declared-read checks before durable intent/input. Literal scoped-root
substitutions are also rejected by model validation; references are checked after
owned bindings resolve. Confirmed historical effects return before this new
admission hook, and no stored predicate or effect is rewritten. Tests prove that
a rejected root reference or trusted admission callback creates no attempt/effect
and calls no input executor. This guard has not been rolled into the installed
broker, so live prevention remains an installation gate.

The parameterized Word frame-focus emitter now takes exact windowTitle and checks
the AXTextArea focused flag inside that window. It is parser-validated only;
the historical live click and its old predicate remain separate evidence.

## Independent feature improvements (October 5, 2026; source only)

External projects are feature references, not implementations to port. The direct
AXSwift adaptation was removed. Mechanize’s existing native checked-state reader
now permits fallback only for explicit missing-value statuses without a payload;
failed or contradictory reads remain uncertain.

Mechanize’s Chrome worker independently shares an in-flight connection attempt
across trusted setup pages, preventing overlapping native transports. Tests cover
explicit reconnect after failure and retain the existing scope/recovery gates.
BrowserOS is a design reference for the independent native Browsers tab. No
upstream controller is invoked, no new dependency is added, and no historical
unknown effect is changed. Source tests are not installed/live qualification.

## Bounded native hierarchy reads (installed observation qualification)

The native snapshot producer now obtains AXChildren via a count and bounded
prefix read, instead of fetching the complete array before limiting traversal.
At most 1001 children are requested for each element. Changed counts, short reads,
malformed arrays and transport errors mark coverage incomplete; unsupported array
APIs do not trigger an unbounded fallback. Budget checks surround the API calls.
Tests cover huge counts, count changes, malformed data and stable small arrays.
This generic behavior is in Mechanize, not an Office skill. A helper-only update
was installed with unchanged broker identity. Fresh MCP observations returned
complete Word and Excel disposable-window trees (100 and 129 nodes respectively).
This is two-window observation qualification, not production-wide AX coverage.
