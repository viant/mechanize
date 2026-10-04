# Durable effect reconciliation design

Status: the first source implementation now includes the generated Datly `ReconcileEffect` transaction, guarded Builder method, host-enrolled native contracts, and closed `mechanize_effect_reconcile` tool. Component, normal integration, and race tests pass. Live deployment qualification is pending. Bare intents without a persisted original outcome and independently recording a stopped boundary when no contract can resolve an effect remain open. The design does not authorize direct ledger edits, replay, or invented postconditions.

## Observed gap

The disposable Chrome menu action reached the Extensions view, but its original step had no postcondition. The authenticated native executor correctly reported `dispatchState=dispatched` and `verificationState=unknown`. Durable execution persisted the effect as unknown and stopped the dependent workflow. A later scoped read showed `Extensions - Google Chrome` and an `AXWebArea` named `Extensions`; that observation was never committed as reconciliation evidence.

Bounded facts from the saved state/read logs:

- Run: `f3b7f66a81da04261cb3101214cf6025688840ef198b0da0f938f11f8cd32196`.
- Immutable plan: `78548720e58fda7720b1c4c680d938b4826c683d5911a7f510647fae1b3c6322`.
- Original attempt: `f2d0e393fee0fc6e56bc40986659375028765444e27ff7681c1a17f0cb1f5153`.
- Effect: `f87cae7e1a0d6643bde70c1df06d9ef30c8e595dc02e1678cbae01f25bb921d2`.
- Saved run revision: 3; saved effect revision: 2; saved durable status: `running`.
- Separately reported Endly operation state: `executionStatus=failed`, `verificationState=unknown`.
- Effect state: `unknown`; original outcome has `postcondition=null`.
- Target: `com.google.Chrome`, PID `4464`, kernel start token `1790968111:309052`.
- Original business key contains `application`, `processBirth`, and `task` fields.

These are historical saved facts. Their revisions, runtime quiescence and process identity must be loaded and verified again before any production reconciliation. The saved observation is diagnostic evidence, not a fresh authorization or a durable outcome proof. The raw observations are intentionally not copied here.

## Existing behavior and supported boundaries

`engine/durable/execute.go` evaluates an enrolled postcondition only during the original action path, when the immutable step contains one. It commits `confirmed` only after independently verified output; dispatch alone becomes `unknown`.

`Builder.LoadResume` rejects effects outside `confirmed`/`absent` before admitting further execution. `engine/recovery/context.go` rejects unknown effects before preparing repair evidence or invoking the planner. `mechanize_state_patch` cannot alter objectives, history or the effect ledger. Runtime control cleanup reconciliation is a separate operation and cannot confirm UI/business effects.

The generated `CommitOutcome` component's authored hook accepts an existing `intent`/`unknown` effect and requires effect CAS plus an outcome event. It is an internal persistence primitive, not an exposed trusted reconciliation API: its current hook does not establish an independently evaluated reconciliation contract or bind a late verification to an inhibited runtime. Calling it directly with client-authored `verified` evidence would bypass the missing production boundary.

At the time of the live audit, the installed runtime had no safe exposed API that adopted this later menu observation into the original unknown effect. `engine/durable/README.md` explicitly lists the generated reconciliation/adoption use case as a remaining gate.

## Runtime stopped state and durable status

The operation's failed execution state and the durable run's `running` status describe different records. Neither implies that the effect is confirmed, and a stale durable `running` value should not make the UI falsely imply active execution. Conversely, a failed operation alone cannot prove all overlapping native work has stopped.

Add a bounded generated stopped-boundary transaction, guarded by host-verified Endly operation termination plus native input inhibition/cleanup evidence. It CAS-updates the exact run revision to a truthful stopped state (`paused` under the existing status vocabulary), appends an `executionStopped` audit record and projects `needsAttention` because unresolved effects remain. It preserves every attempt/effect and its uncertainty; it grants no resume authority. If the status vocabulary is extended with `needsAttention`, its meaning must remain stopped execution with unresolved disposition, not completed work.

This route must explicitly permit preserving unknown effects, unlike the existing general `TransitionRun` route, which rejects them. The trusted runtime guard supplies the stop evidence; a caller-provided status or operation ID does not. A missing/uncertain quiescence proof leaves the existing records unchanged and reports attention. The stopped-boundary admission can precede contract evaluation and remains useful even when no adoption contract exists. Reconciliation then loads the new current revision rather than using historical revision 3.

No stopped transition is performed by this audit. Implement and qualify this guarded route before using it on the current run.

## Proposed API and trusted method

Add a host-owned `Builder.ReconcileEffect` route and, after qualification, `mechanize_effect_reconcile`. A request identifies the owned run, immutable plan, original attempt/effect, expected run/effect revisions, and an enrolled reconciliation-contract reference/version. It carries no executable script, SQL, replacement effect class, caller-authored success boolean, raw native ref, or evidence that the host trusts without verification.

The method performs these operations without dispatching any mutation:

1. Authenticate principal and ownership; acquire the existing per-user durable lock and a runtime reconciliation guard that proves overlapping execution is inhibited and the original operation has stopped. A stale `running` database status cannot supply quiescence, and an unknown effect must not make quiescence impossible to establish.
2. Load the original immutable envelope, inputs, attempt, effect, outcome audit and current run through generated readers. Verify canonical IDs, original step index/ID, plan hash, namespace, business key and expected revisions. Reject ambiguous lineage, missing records and inconsistent prior evidence.
3. Resolve the persisted step's `effect.reconcile`, or a separately enrolled qualified contract matching the exact original action, surface, selector, app/version and business identity. A missing original predicate is not authorization to accept an arbitrary new predicate or modify the old plan. A separately qualified adoption contract is required for this case; if none exists, return `needsAttention` with the effect unchanged.
4. Acquire exact observe consent and evaluate that read-only contract through the enrolled evaluator. Bind the native selector to the original process fingerprint and authorized window/ancestor boundaries. Use fresh helper evidence, bounded reads, explicit attribute policy and exact cardinality. Recheck the runtime guard and process identity at the evidence boundary.
5. Classify the result using the qualified contract. Commit only a proven supported resolution through one generated Datly transaction, retain original intent/outcome audit, and require confirmed commit evidence before reporting a resolved effect.
6. Reload the committed projection through a generated reader. Resume remains a separate explicit Endly operation under normal admission and consent; reconciliation performs no replay or new UI action.

Read-only observation can remain available while an effect is unknown. The mutation barrier remains in force until a confirmed reconciliation commit establishes the original effect's disposition.

## Evidence, scope and authority

A reconciliation contract is selected by trusted host policy, not by a planner's claim or the MCP request. It must explain exactly what a true/false/unknown result proves for the original action and which authority is sufficient.

For a qualified UI-navigation effect, observational authority can establish a bounded UI postcondition. In the menu example, a qualified Chrome/AX action contract would bind the exact original menu action to opening the Extensions view in the original disposable process, and independently verify the resulting view. It confirms that UI effect only. It cannot establish extension installation, successful workflow completion, or the absence of other business effects.

Generic native press/fill retain conservative classification. Seeing the destination view later does not by itself prove the complete effect of an arbitrary original press. If the original action has no registered navigation/adoption contract, reconciliation must leave it unknown. The contract must not silently reinterpret an external non-idempotent action as reversible because its visible result looks harmless.

Consequential business effects require an authoritative business adapter and the original exact entity/idempotency key. An observational native value equality cannot confirm payment, submission, installation or another business outcome. The existing evaluator's freshness and authority limits must remain enforced.

Native evidence must bind namespace, bundle, PID and start token; helper epoch and fresh target generation; exact authorized scope; contract reference/version/hash; original run/plan/step/attempt/effect and business key; observation timestamps and evidence provenance. Redacted evidence references remain scoped and encrypted according to existing artifact policy. Do not persist entire AX trees or sensitive attribute values merely to obtain a resolution.

A different process with the same bundle or a reused PID cannot adopt the original effect. If the contract explicitly supports an app restart, that requires a distinct qualified continuity proof tied to the original business entity; the default native navigation contract does not support it.

## Unknown, absent and retry rules

- `true` with sufficient qualified authority and fresh complete evidence can confirm only the declared original effect.
- `false`, incomplete evidence, stale birth identity, expired consent, unavailable adapter, or an unmet current view predicate leaves the effect unknown unless the contract independently proves absence.
- A dispatched action is not absent merely because its resulting view is no longer visible. Navigation may have happened and then changed.
- Absence requires explicit trustworthy non-dispatch evidence or an authoritative complete absence/idempotency contract. Preserve the current stronger resume rule: a generic `absent` effect requires persisted `notDispatched` evidence. Supporting authoritative absence after dispatch needs a separately designed retry-admission proof; do not synthesize `notDispatched` or relax `LoadResume` incidentally.
- A confirmed effect creates verified progress and is skipped on resume. An absent effect is not a completed milestone and does not authorize overwriting its original attempt or blind retry.
- Unknown remains visible on cancellation, process restart and timeout. Reconciliation does not change it to confirmed merely to release a fence or make a workflow runnable.

## Generated transaction and audit design

Create authoritative DQL and Datly v1 generated `ReconcileEffect` writer/reader components. Keep product persistence in generated components; no direct product SQL or service/DAO shortcut. The authored ingress and lifecycle hooks must enforce ownership, exact original relationships, canonical correlation, immutable business identity, trusted reconciliation provenance and CAS.

The single transaction should:

- CAS the current run revision and original effect revision from the loaded values, and accept only unresolved `intent`/`unknown` prior state.
- Preserve the original attempt/effect IDs, original plan and inputs, intent event, original dispatch/outcome event and any existing milestones.
- Append a dedicated reconciliation record/event with a stable request identity, contract identity, original evidence reference, independently evaluated late evidence, disposition and audit sequence from the durable event cursor.
- Update the current effect projection to the supported resolved state with reconciliation evidence. Do not rewrite the original receipt's dispatch or verification fields.
- For confirmation, append a verified milestone for the exact original step/attempt and only persisted outputs justified by the contract. Never fabricate missing bound return values; if required outputs cannot be reconstructed safely, the run remains non-resumable.
- Record the safe stopped boundary consistently through the dedicated guarded stopped-boundary graph described above, or the reconciliation graph when it receives the same trusted quiescence proof. An ordinary permitted transition can be used after all effects resolve. Do not rely on the existing transition route to clear unknown effects first; it rejects them by design.

The writer must fail if any expected reference, revision, business key, runtime proof or provenance differs. Existing resolved effects return only a matching committed reconciliation projection through the reader. A lost commit acknowledgement is reconciled by exact immutable reconciliation ID and canonical content/hash; it never causes UI replay or a second contradictory reconciliation event.

Unknown evaluation need not create a resolved milestone. If policy records an inconclusive reconciliation attempt, preserve `unknown` with a distinct append-only audit record and bounded attempts; never treat an attempted evaluation as confirmation.

## Tests and integration gates

Required fixture tests:

- Original dispatched unknown with a qualified persisted reconciliation predicate confirms through a fresh read; original action dispatch count remains one.
- Original step without postcondition/reconcile remains unknown without a matching trusted adoption contract; client-authored predicates and success claims fail.
- A qualified UI-navigation adoption contract confirms only navigation with observational authority; a business contract requiring authoritative evidence rejects the same UI evidence.
- Exact process fingerprint forwarding; same-bundle foreign instance, PID reuse, absent process and changed business key fail before evidence adoption.
- Stale/future/incomplete/ambiguous evidence, expired consent and adapter failure leave unknown; false current view does not imply absence.
- Runtime still active or uncertain helper cleanup denies admission; safe reconciliation guard works when historical durable status is `running` and original operation is stopped.
- Cross-principal, stale plan/run/effect revisions, forged original relationships and duplicate conflicting reconciliation requests fail atomically.
- Generated graph preserves original IDs/audit rows, appends the correct event cursor and milestone, and exposes the committed projection.
- Inject lost writer acknowledgement, process crash before/after commit, key outage and concurrent resume: exact reader reconciliation either proves the one committed resolution or preserves the mutation barrier.
- Resume skips confirmed original mutation, uses only justified outputs and retains original business-key/lineage checks; absence is not replay permission.

Before using this route on the menu run, qualify the trusted Chrome native navigation/adoption contract, generated reconciliation transaction/readback, runtime guard, host/MCP ownership and consent wiring, and no-replay recovery tests. Then repeat fresh exact-instance read-only evidence under the guard and commit through the new route. The historical menu observation alone must not be imported as fresh evidence.

The current run remains unresolved until these gates are met. No database edit, replay, plan-history mutation, forced milestone or status-only transition is an acceptable substitute. This gap is part of the full production recovery objective.
