# Mechanize definition-of-done qualification audit

This audit maps the numbered release gates in [plan.md §33.1](../plan.md#331-product-definition-of-done) to the current implementation and recorded evidence. It uses [AGENTS.md](../AGENTS.md), plan sections 31–36, [implementation.md](../implementation.md), [remaining-gates.md](remaining-gates.md), and current source paths. It is a read-only audit: no tests were run and no live desktop input occurred.

The product definition remains open. Code and fixture success are evidence for bounded slices; they do not qualify signed installation, a live native/Chrome cohort, production credentials, or measured reliability. No completion percentage or reliability score is inferred here. When tracker prose conflicts, the latest source and dated evidence should be checked; older blanket text such as “all gates initially unverified” is not a current progress summary.

## Numbered release gates

| ID | Plan §33.1 requirement | Current implementation and bounded evidence | Remaining proof for release |
| --- | --- | --- | --- |
| DOD-01 | **MCP product:** packaged `viant/mcp` server, stdio and authenticated HTTP, accurate schemas, sessions and reconnect. | `cmd/mechanize/main.go`, `host/host.go`, `mcp/server.go`, `mcp/skills.go`, `mcp/state.go`, `mcp/recording.go`, and `mcp/scenario.go` compose the runtime and typed tools. The disposable `e2e/` gateway/identity cases exercise actual MCP HTTP and tools; latest tracker also records three-skill retrieval coverage. | Build/install a release package on a clean machine; exercise authenticated stdio and HTTP initialization, reconnect, tool/resource/skill schemas, auth expiry and session ownership through that package. Verify every conditional tool matches advertised capabilities. |
| DOD-02 | **Endly automation:** interactive actions and complete scripts preserve lifecycle, conditions, cleanup, cancellation, and failures. | `integration/endly/` lowers and executes through Endly; `mcp/server.go` maps step/script calls and status/cancel to its runtime. Unit and disposable e2e evidence is recorded in `implementation.md` and `e2e/README.md`. | On supported native and real Chrome fixtures, retain actual Endly IDs/task paths/events and prove init/post/condition/defer/error semantics, failed assertions, cancellation during dispatch, and truthful terminal status through the packaged host. A fake executor does not qualify a platform action. |
| DOD-03 | **Datly data layer:** every product read/write is a generated v1 use-case component; one component replaces service+DAO. | `data/source/`, adjacent `data/*/sql/`, generated package assets, `data/host/`, and `engine/durable/` show the selected architecture. `data/README.md` records SQLite acceptance for generated operations and identifies gaps. `data/provision.go` is the narrow infrastructure path. | Complete the generated-component inventory and deterministic regeneration review. Prove all product reads/writes, including new recovery/retention/grant/artifact flows, stay on generated components; close the documented atomic `CreateRun` audit/correlation, immutable repair, retention and connector eviction/reopen gaps. No source scan/regeneration run was performed for this audit. |
| DOD-04 | **Scy security:** verified issuer, audience, algorithm, time and scopes; protected credentials; no unverified identity fallback. | `auth/verifier.go`, `auth/principal.go`, `host/config.go`, `host/host.go`, and `security/keychain/` use Scy verification and verified context. Fixture cases are recorded in `auth/`, `e2e/`, and the tracker. Native peer proof is in `auth/nativepeer/`. | Run the full negative-claim and credential-rotation suite through packaged stdio and HTTP, including signature, issuer, audience, algorithm, expiry/not-before, missing scope, identity omission, forged principal, namespace fallback, cross-issuer collision, and secret-redaction cases. Provisioned Scy/Keychain enrollment and actual installed peer acceptance remain open. |
| DOD-05 | **Per-user isolation:** no cross-user access to plans, runs, state, events, artifacts, recordings, sessions or connectors. | Principal-derived namespaces and generated input scoping appear in `auth/`, `data/scope.go`, `data/*/authorization.go`, `host/`, and per-user durable/catalogue services. Fixtures cover selected cross-user cases. | Demonstrate two authenticated users concurrently across every object/tool, caches, cursors, connector eviction/reopen and restart; exercise forged IDs, namespaces, event/artifact references and session/operation IDs. Also prove both users contend for one physical desktop-wide lease. A per-user database alone is not desktop isolation. |
| DOD-06 | **Shared DSL:** text and structured inputs normalize to one typed model across native and Chrome. | `model/`, `script/`, and `mcp/source.go` implement typed validation and DSL/JSON/YAML frontends; parser/compiler cases and mixed-surface fixtures are present. | Finish fuzz/round-trip and policy-equivalence evidence for all released frontends and capabilities, then run qualified mixed native/Chrome scripts on exact supported cohorts. Parser acceptance does not prove backend capability or runtime support. |
| DOD-07 | **Native/Chrome control:** semantic targets, correct outcome checks, truthful support and safe handoff. | Native source is in `native/macos/` and `backend/darwin/`; Chrome is in `extension/chrome/` and `backend/chrome/`. Both expose bounded semantic adapters and fixture coverage. `host/host.go` currently supplies lease epoch zero and `AllowMutation: false`, so the default configured host does not grant DSL mutation authority. | Complete the physical desktop fence and consent-to-dispatch cleanup path, then qualify a signed/installed helper on a disposable Mac with actual AX/TCC permissions. Qualify an enrolled signed Chrome profile across supported versions, dialogs, reconnect, stale/late receipts and app/browser handoff. Do not treat lower-level press/fill code or a reported capability as production control proof. |
| DOD-08 | **Recording:** employee demonstration becomes a parameterized script with provenance, redaction and gap review. | `backend/chrome/recording.go`, `engine/recording/`, `host/recording.go`, `mcp/recording.go`, `extension/chrome/recorder.js`, and generated event components implement a conditional Chrome path. MCP registers start/pause/stop/status/export only when its recording service is wired; the host builds that service only with Chrome. Recording requires enrolled ceiling and explicit consent. This updates the older “tools not wired” note: source wiring now exists, but does not equal production qualification. | Reconcile the `recording` capability report with actual tool availability (in `backend/chrome/gateway.go` the capability is conditional). Complete consent UI/native grant enforcement and real-profile tests for sensitive fields, redaction failure, navigation loss, gaps, bounds, stop uncertainty and retention. Persist/export, review, then replay with changed inputs/layout in an isolated fixture and independently verify its outcome. Native recording is not established. |
| DOD-09 | **Durable effects:** commit intent before dispatch, verify and record outcome after, block unsafe replay. | `engine/durable/execute.go`, `engine/durable/effect_key.go`, `engine/durable/resume.go`, `data/beginattempt/`, and `data/commitoutcome/` encode stable attempt identity, confirmed commit gating and unknown barriers. Generated and Endly fixtures are recorded in `implementation.md`. | Inject crashes at every intent/dispatch/receipt/outcome boundary in the full broker/Endly/Datly path. Check independent authoritative effect counts for no duplicates and wrong-entity cases. Do not infer exactly-once behavior from a successful API return or fixture receipt. |
| DOD-10 | **Checkpoint/resume:** reconstruct after crash, resume only verified progress, report partial restore honestly. | `engine/durable/checkpoint.go`, `engine/durable/resume.go`, `host/resume.go`, `mcp/resume.go`, artifact publication and generated checkpoint components implement guarded metadata and resume fixtures. Confirmed prefixes are skipped; unknown effects block. | Kill and restart the broker, helper, Endly process and host at relevant boundaries. Prove session/task reconstruction, checkpoint freshness and app/display compatibility, per-object grants, partial unsupported-state reporting, and resume under a newly approved session/fence. Existing builder-restart fixtures are narrower than process-death restore. |
| DOD-11 | **Adaptive recovery:** repair supported changes within bounds while retaining objective, entity and permission constraints. | `recovery/`, `engine/durable/objective.go`, `integration/endly/resume.go`, and `scenario/` provide typed proposal/validation and guarded pause/resume code. MCP has scenario publish/list/select tools (`mcp/scenario.go`), but selection is proposal-only. `host/host.go` currently constructs the scenario service without trusted Environment, Qualify or VerifyProvenance callbacks, so packaged selection fails closed for missing fresh qualification. Recorded focused objective evidence proves safe paused behavior for known failures and barriers for unknown effects. | **Active gate:** repair admission/revision/budget checks, original-ledger lineage, and actual retry execution are not complete. Preserve original attempts/effects, prove a changed revision/new attempt with no duplicate confirmed prefix, require read-only prefix proof or attention, and run held-out UI perturbations with wrong-repair/unknown-effect cases. A proposed or selected repair is not an executed recovery. |
| DOD-12 | **Business completion:** only an authoritative qualified objective oracle can establish success. | `objective/`, `engine/durable/objective.go`, `integration/endly/objective.go`, and `mcp/server.go` separate execution from business status. Disposable receipt fixtures cover exact-key success, wrong-key/offline unknown and authoritative false. | Enroll real per-adapter independent outcome providers and qualify them against supported app/version/entity cohorts. Test stale, duplicated, wrong-key and false-success receipts. Packaged hosts without a provider must continue to report unverified/unknown. |
| DOD-13 | **Reliability:** meet plan §22 cohort confidence thresholds with honest counts. | Cohort and qualification types exist in `scenario/` and related plan/selector code; no production reliability measurements are recorded. | Follow the proposed §22.4 targets without claiming they have been met: ≥99% observed deterministic critical-workflow completion with a 95% lower bound ≥98% and ≥1,000 varied trials per nominated critical workflow; core semantic-action lower bound ≥99.5%; deterministic recovery lower bound ≥95% with ≥300 labeled perturbations per recovery family. Also require zero observed false-success and duplicate consequential effects, 100% injected-unknown barriers, cancellation/observe/capture latency gates, and a 24-hour broker soak. Report raw counts, cohort versions, confidence intervals, exclusions, rescue/attention counts and incidents. Do not substitute fixture pass counts or invented percentages. |
| DOD-14 | **Operational stability:** bounded queues/storage, responsive stop, safe leases and compatible upgrades. | Bounds and stop/uncertainty handling appear in `backend/`, `session/`, `artifact/`, `host/` and `engine/durable/`. Unit/race results are recorded for bounded components. | Run sustained soak and contention tests; disk-full, queue overflow, key-unavailable, permission revocation, helper hang, cleanup uncertainty, restart, migration, version-skew and prompt-stop scenarios. Confirm no stale input authority and recoverable state after each. |
| DOD-15 | **Deployment/support:** reproducible signed identities, linked sources/resources, clean install/upgrade/rollback and operator docs. | `scripts/build-development.py` and `docs/developer-mode.md` produce an ad-hoc development package and verify its local hash pins. It is not Developer ID signing or an installed build. `data/README.md` documents source-backed Datly deployment. | Developer signing prerequisites were absent at the last recorded check. Complete Developer ID signing/notarization, signed extension/helper/native identities, Scy enrollment, source/resource and Endly packaging, clean-machine install, upgrade/rollback, version skew, TCC attribution and operator runbooks. Hash-pin verification of an ad-hoc build does not satisfy this gate. |

## Crosswalk for plan sections 31–36

- **§31, Datly and identity isolation:** DOD-03 through DOD-05 cover the generated component boundary, verified namespace routing and shared desktop contention. In addition to the fixtures, release evidence must prove connector immutability/eviction/reopen, every product-data path through generated components, and same-operation atomicity. Keep all artifact, recording, checkpoint, grant and event reads under the same identity checks.
- **§32, Endly orchestration and repair:** DOD-02, DOD-09 through DOD-12 cover Endly lifecycle, intent/outcome order, recovery and business completion. Endly must remain the single workflow scheduler. A Datly commit must be confirmed before input; no retry or repair path may dispatch while an effect is unresolved.
- **§34, Scy and MCP:** DOD-01, DOD-04, DOD-05 and DOD-15 cover the required libraries, strict identity, protected transport/resources and installed credentials. Fixture HTTP/stdio tests do not prove deployed authentication, and application grants do not replace Scy or macOS controls.
- **§35, bundled skills and e2e:** `skills/`, `skills/embed.go`, `mcp/skills.go`, `e2e/` and the tracker record bundled runtime guidance and an executable fixture suite. The suite is bounded acceptance, not the product DoD. Preserve independent skill retrieval through native skills support and MCP tools/resources, then add end-to-end LLM routing evidence without relaxing security gates.
- **§36, native permission/activity interface:** `native/console/`, `host/localrpc/`, `host/consent*.go`, `consent/`, `auth/nativepeer/` and `security/keychain/` implement/test the UI, protocol and broker slices. The current ad-hoc app remains uninstalled/disconnected without provisioned identity/credentials. Production proof must include signed peer authentication, separately approved exact scope/purpose/mode, one-use consumption, revoke through confirmed cleanup, helper-specific TCC status, and re-observation after approval.

## Recovery evidence and active work

The current recorded focused Endly+Datly objective recovery fixture passed in
54.513 seconds. It covers a known stopped read/locator failure becoming paused
and unverified, preserving the confirmed prefix, explicit same-session resume,
and unknown/cancelled effect barriers. The known-absent loader fixture
`TestKnownAbsentResumeRemainsPendingWithoutReplayingOldIntent` is recorded at
about six seconds and proves the old absent intent is not replayed and the
original step remains pending. Source locations are
[`engine/durable/objective_test.go`](../engine/durable/objective_test.go) and
[`engine/durable/resume_test.go`](../engine/durable/resume_test.go).

These fixture results do **not** prove that a new recovery revision is admitted,
that a new attempt with correct lineage actually retries the action, or that
the end-to-end retry survives a crash. Those are active implementation gates:
repair admission, immutable revision/budget accounting, original-ledger
lineage, and actual retry dispatch. Retain the prior confirmed ledger and make
the new attempt identity explicit; if read-only prefix proof is absent, request
attention rather than assuming that the old plan prefix is safe.

The latest broad `go test ./...` and `go vet ./...` results were recorded before
the active recovery edits. They are useful baseline evidence only, not a claim
about the current working tree. No tests were rerun for this audit. After those
edits stabilize, rerun focused durable/objective/resume/MCP fixtures, the full
Go suite and vet, then the disposable Endly e2e suite. A passing rerun closes
only the exercised fixture cases.

## Coherent next qualification gates

1. **Finish recovery correctness first.** Implement repair revision and budget
   admission, lineage-preserving attempt identity, explicit known-absent retry,
   safe read-only-prefix treatment, and crash-boundary reconciliation. Prove
   original confirmed actions are skipped, old intent IDs are never replayed,
   new intent is committed before a new dispatch, and unknown effects stop.
2. **Freeze and revalidate integration.** After active edits settle, run focused
   recovery/Data/Endly/MCP tests, then the complete Go suite and vet; rerun the
   Endly e2e fixture suite. Record commands, duration and outcomes in
   `implementation.md`. Do not carry forward green evidence across untested
   edits.
3. **Enroll trusted qualification providers.** Supply verified environment,
   provenance, cohort qualification and independent outcome callbacks; make
   scenario selection and objective completion remain fail-closed without
   them. Test exact objective/entity/input/surface/profile/version matching,
   stale evidence, ambiguity, permissions and authoritative negative results.
4. **Complete packaged platform acceptance.** Secure Developer ID signing and
   notarization plus Scy/Keychain enrollment. Install on a disposable Mac,
   validate helper-specific TCC, exact-window capture, visible native grants,
   cancellation/revoke cleanup and native fixture outcomes. Separately enroll
   supported disposable Chrome profiles and test navigation, recording gaps,
   late receipts, stop/reconnect and independent outcomes.
5. **Qualify reusable workflows.** Exercise recording redaction and export,
   change inputs and UI geometry, replay in an isolated fixture, and verify the
   business result independently. Test checkpoints and restart/restore at
   broker/helper/Endly crash boundaries; clearly report unsupported state.
6. **Measure and release.** Complete the two-user isolation matrix, soak,
   resource pressure, permissions, migration and upgrade/rollback cases. Gather
   the per-cohort trial data required by plan §22 and publish confidence bounds
   before declaring a supported matrix or production reliability.

External prerequisites currently include a valid Developer ID signing identity,
trusted Scy credentials and enrollment, disposable permission-granted macOS
fixtures, and a real enrolled Chrome test profile. These prerequisites have not
been established by the fixture results in the tracker.
