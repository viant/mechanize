# ReconcileEffect

Private generated Datly PATCH component for one qualified confirmed effect. Its
single transaction CAS-updates the owned run to `paused`, CAS-confirms the original
effect, appends a verified original-step milestone, and appends an
`effect_reconciliation` event. It never dispatches input, clears another unknown
effect, replaces an original attempt, edits the original plan, or claims business
objective success.

The authoritative graph is `data/source/reconcileeffect/ReconcileEffect.dql`.
Generate with operation-based `datly transcribe patch`; application behavior lives
in `authorization.go` and create-once `lifecycle.go`. Existing schema is unchanged.

The trusted Builder must hold its stopped-runtime admission guard, bind verified
principal/data scope plus `data.WithStateMutationPermit`, select and evaluate a
qualified original-action contract, then mint
`data.WithReconcileEffectAuthority(ctx, authority)`. Client JSON cannot mint the
private context capability. Obtain the detached canonical authority with
`data.RequireReconcileEffectAuthority` before constructing the generated body.

`ReconcileEffectEvidence` carries the contract ID/hash, required authority,
freshness bound, evaluator result, and compatible `integration.StepResult`.
Only fresh true evidence with sufficient observational/authoritative authority
and nonempty evidence references is accepted. Original dispatch state and bound
output cannot change. The new observation may be omitted to avoid duplicating a
large tree already retained in the original audit. Authoritative proof must match
the original business key. UI confirmation does not authorize `succeeded`.

`EvidenceJSON` remains canonical `integration.StepResult`, compatible with
existing durable resume/adoption readers. `AuditPayloadJSON` carries the full typed
proof, original evidence hash, exact original correlation and prior run/effect
revisions. The original outcome event is retained unchanged.

Generated input construction:

- `ReconcileEffectInput.SetNamespace` and exactly one `SetReconcileEffect` Run.
- Run: namespace, original ID, expected revision, status `paused`, updatedAt equal
  to authority.Now; exactly one Effect and Event. Omit plan/creation/operation
  correlation columns and all auxiliary Plan/Attempt rows.
- Effect: original namespace/ID/run/attempt, expected revision, state `confirmed`,
  canonical authority.EvidenceJSON, and exactly one new Milestone. BusinessKey
  may be omitted; an explicit value must match the original.
- Milestone: canonical existing original-step milestone ID, namespace/run/attempt,
  state `verified`, identical canonical verified evidence.
- Event: authority audit ID, original namespace/run/attempt, next immutable event
  cursor, kind `effect_reconciliation`, authority.AuditPayloadJSON and authority.Now.

Use generated setters for presence. The hooks advance working run/effect tokens
once; generated concurrency-token guards preserve captured expectations and
provide atomic IfMatch execution checks. Ingress rejects foreign explicit links
before generated parent reconciliation. Auxiliary scoped Plan/Attempt reads verify
actual immutable plan content/step hashes and canonical original identities.
Existing milestones/events cannot be overwritten. Other unknown effects remain.

The initial route requires a persisted original outcome/evidence receipt with
`dispatched` or `unknown` dispatch state. A bare committed intent without any
outcome receipt fails closed; supporting that crash boundary requires explicit
absence-of-receipt provenance and tests, not a fabricated original receipt.
There is no false-to-absent or retry route.

A successful writer return is insufficient unless its public Datly completion
outcome reports `CommitConfirmed()`. A lost response is recovered through the
existing generated `LoadRun` reader, matching exact original correlation,
reconciliation event ID/payload, milestone and resulting effect proof. Audit
prior revisions identify the original request even after the run advances.
Repeating the writer rejects a resolved effect; it does not append another event.
The Builder owns idempotent readback, stopping admission, and explicit later Endly
resume under renewed consent. No writer hook performs resume or replay.

Verified with the real generated SQLite runtime: atomic confirmation, unchanged
original audit/correlation, unrelated unknown preservation, twelve forged/CAS
rejections, concurrent one-winner CAS, lost committed acknowledgement/readback,
and immutable proof capability. Production registration and runtime/MCP guard
integration belong to the host; a private fixture does not qualify those gates.
