# Mechanize definition-of-done qualification audit

This checklist maps release requirements to checked-in implementation and fixture
sources. It complements [remaining gates](remaining-gates.md) and the
[architecture overview](../README.md). Historical planning, agent-instruction and
implementation-tracker files referenced by earlier versions of this audit are
not present in this checkout; the requirements and evidence pointers below are
self-contained.

The product release remains unqualified by this audit. Source and fixture coverage
do not establish signed installation, live native/Chrome behavior, provisioned
credentials or measured reliability. Test results must identify the revision,
command and scope; a previous passing run does not validate later edits.

## Release checklist

| ID | Requirement | Current implementation and fixture sources | Remaining release proof |
| --- | --- | --- | --- |
| DOD-01 | **MCP product:** packaged server, authenticated stdio/HTTP, accurate schemas, sessions and reconnect. | [Host composition](../host/host.go), [gateway](../mcp/server.go), [skills](../mcp/skills.go), and [disposable acceptance suite](../e2e/README.md). | Exercise installed-package transports, enrollment, reconnect, expiry, session ownership and conditional tool/capability consistency. |
| DOD-02 | **Endly automation:** preserve workflow lifecycle, conditions, cancellation, cleanup and failure status. | [Runtime](../integration/endly/runtime.go), [shutdown tests](../integration/endly/shutdown_test.go), and [host shutdown tests](../host/shutdown_test.go). Host shutdown drains the runtime before durable storage closes. | Verify lifecycle and actual task/session identities on supported native and Chrome fixtures, including failure and cancellation during dispatch. |
| DOD-03 | **Generated Datly data layer:** product operations use generated v1 components. | [Data architecture](../data/README.md), [component registration](../data/host/host.go), and [regeneration script](../data/scripts/regenerate.sh). Reconciliation and stop-boundary source packages are included in regeneration. | Run deterministic regeneration with the pinned Datly tool and provisioned discovery schema; review all generated changes, transaction boundaries, retention and connector eviction/reopen behavior. |
| DOD-04 | **Scy security:** verified claims, protected credentials and no identity fallback. | [Verifier](../auth/verifier.go), [verifier tests](../auth/verifier_test.go), [native peer verification](../auth/nativepeer/README.md), and [Keychain integration](../security/keychain/README.md). | Qualify negative claims, credential rotation/redaction, packaged transports and signed installed-peer enrollment. |
| DOD-05 | **Per-user isolation:** protect every plan, run, state, event, artifact, recording and session. | [Principal identity](../auth/principal.go), [scope](../data/scope.go), [durable host binding](../engine/durable/builder.go), and [artifact storage](../artifact/store.go). | Exercise two-user concurrent access, forged IDs/cursors, restart and connector lifecycle across all tools; prove contention for the same physical desktop fence. |
| DOD-06 | **Shared typed DSL:** text and structured inputs normalize consistently across surfaces. | [Parser](../script/parser.go), [compiler](../script/compiler.go), [workflow validation](../model/workflow_validate.go), and [MCP source parsing](../mcp/source.go). | Complete fuzz/round-trip and policy-equivalence evidence, then qualify mixed native/Chrome scripts against the advertised supported capabilities. |
| DOD-07 | **Native and Chrome control:** semantic targeting, safe handoff and truthful outcomes. | [Native enrollment](../host/native_launch_config.go), [native control](../host/native_control.go), [web control](../host/web_control.go), and [native full-path fixtures](../host/native_launch_integration_test.go). Configured native launch/semantic authority is wired through `Host.New`; control remains gated by enrollment, identity, fence, readiness and consent. | Qualify signed installed helpers and enrolled real Chrome profiles, TCC permissions, dialogs, navigation, late receipts and stop/revoke cleanup. |
| DOD-08 | **Recording:** parameterized scripts with provenance, redaction and gap review. | [Host recording](../host/recording.go), [native recording](../host/native_recording.go), [durable event storage](../engine/durable/recording.go), and [compiler](../record/compiler.go). The host wires the service when Chrome or native recording is configured. | Qualify real-surface redaction, gaps, bounds, retention, stop uncertainty, export and changed-input/layout replay with independent business verification. |
| DOD-09 | **Durable effects:** commit intent before input and block unsafe replay. | [Execution](../engine/durable/execute.go), [reconciliation](../engine/durable/reconcile.go), [stop boundary](../engine/durable/stop_boundary.go), and [retry tests](../engine/durable/execute_retry_test.go). | Inject full-process failures at every intent/dispatch/receipt/outcome boundary and independently count effects, including wrong-entity and duplicate-effect cases. |
| DOD-10 | **Checkpoint/resume:** reconstruct verified progress and report partial restoration. | [Checkpoint publication](../engine/durable/checkpoint.go), [resume](../engine/durable/resume.go), and [host resume](../host/resume.go). | Prove broker/helper/Endly process-death reconstruction, checkpoint freshness, app/display compatibility, grants and partial unsupported-state reporting. |
| DOD-11 | **Bounded recovery:** preserve objective, entity, permissions and original effect history. | [Repair admission](../data/repairadmit/lifecycle.go), [lineage integration test](../engine/durable/lineage_test.go), [native recovery flow tests](../host/native_recovery_flow_test.go), and [scenario selection](../scenario/README.md). Immutable revision/budget admission and actual repaired-step dispatch have fixture coverage. | Enroll trusted environment/provenance/cohort and recovery-evidence providers. Qualify read-only prefix treatment, held-out perturbations, wrong repairs and crash recovery. Proposal selection alone does not establish successful execution. |
| DOD-12 | **Business completion:** require a qualified independent objective oracle. | [Objective evaluation](../objective/evaluator.go), [durable completion](../engine/durable/objective.go), and [MCP status mapping](../mcp/server.go). | Qualify per-adapter providers, exact business keys, stale/duplicate/wrong-key receipts, authoritative negatives and unavailable-evidence behavior. |
| DOD-13 | **Measured reliability:** publish honest cohort counts and confidence bounds. | [Scenario qualification](../scenario/select.go) supplies selection contracts; source coverage does not establish a reliability rate. | Collect supported-cohort trials with raw counts, versions, exclusions, incidents, attention/rescue counts and confidence intervals. Proposed targets are retained below, not reported as achieved. |
| DOD-14 | **Operational stability:** bounded resources, responsive stop, safe leases and upgrades. | [Supervisor](../session/supervisor.go), [artifact storage](../artifact/store.go), [native control](../host/native_control.go), and [web control](../host/web_control.go). | Run sustained contention/soak, disk-full, overflow, key outage, permission revocation, helper hang, uncertain cleanup, restart, migration and version-skew cases. |
| DOD-15 | **Deployment/support:** reproducible signed install, upgrade/rollback and runbooks. | [Development packaging](developer-mode.md), [installation](local-installation.md), and [source-backed data deployment](../data/README.md). | Demonstrate clean-machine Developer ID signing/notarization, enrollment, linked resources, upgrade/rollback, TCC attribution and operator procedures. Ad-hoc hash-pin verification does not satisfy release qualification. |

## Recovery evidence and its limits

[TestAdmittedRepairResumesThroughEndlyWithoutRelabellingLedger](../engine/durable/lineage_test.go)
exercises immutable repair admission and Endly resume with preserved original
attempts and an independent fixture objective oracle. The
[retry tests](../engine/durable/execute_retry_test.go) and
[resume tests](../engine/durable/resume_test.go) cover related replay barriers.
These are implemented fixture paths, not pending implementation claims. Actual
process-death recovery and qualified live perturbations remain open.

The host creates scenario selection without trusted environment, qualification
or provenance callbacks by default. Native recovery evidence is supplied only
when trusted options configure it. Missing evidence must continue to block
admission; source wiring does not establish a provisioned production provider.
See [host composition](../host/host.go).

## Proposed measurement targets

The earlier audit proposed at least 99% observed completion with a 95% lower
confidence bound of 98% and at least 1,000 varied trials per nominated critical
workflow; a core semantic-action lower bound of 99.5%; and a deterministic
recovery lower bound of 95% with at least 300 labeled perturbations per recovery
family. These remain proposed acceptance targets requiring an agreed cohort and
measurement protocol. No achievement is claimed. Include zero observed
false-success and duplicate consequential effects, all injected-unknown barriers,
explicit cancellation/observation/capture latency gates and a 24-hour broker soak.

## Next qualification work

1. Run focused recovery, consent, native/Chrome control and shutdown fixtures,
   then the full Go suite, vet, extension suite and disposable Endly acceptance
   suite. Record commands, revision, outcomes and limitations alongside results.
2. Regenerate all data components against the pinned Datly tool and provisioned
   schema; review generated differences and transaction/authorization invariants.
3. Enroll trusted outcome, environment, provenance, cohort and recovery-evidence
   providers, retaining blocked admission when evidence is unavailable.
4. Install signed packages on disposable macOS/Chrome fixtures and qualify TCC,
   revocation, cleanup, reconnect and real process-death boundaries.
5. Qualify recording/export/replay, cross-user isolation, resource pressure,
   upgrade/rollback and measured workflow reliability before declaring support.
