# Verified undesired effects and safe repair

## Current support

There is no supported route for committing a verified undesired UI outcome.
`Builder.Execute` records `confirmed` only when the immutable expected
postcondition is true. A false or unavailable postcondition leaves the effect
`unknown`. `ReconcileEffect` has the same success-only shape: its enrolled
predicate must be true, and the commit hook writes a verified `StepResult` and
verified milestone. Reusing that path for an alternate UI state would claim the
expected step succeeded. Writing `absent` would be false because the original
dispatch was not proven absent.

Resume rejects every unresolved effect. Recovery currently rejects `unknown`
before planning, accepts only `committed` and `absent` effect records, and
requires all remaining mutations to retain their original business effect and
arguments. It has no disposition for a known failed step or a compensating
effect. Correlation among run, plan, attempt, effect and audit records proves
which history is being examined; correlation alone does not prove which UI
result the action caused.

## Keep execution, expectation and objective results separate

Add a durable `verifiedUndesired` effect disposition, distinct from
`confirmed`, `absent` and `unknown`. It means a trusted, action-specific
contract established both that the original action produced a specified
undesired result and that the immutable expected postcondition was false. It
does not mean the expected step succeeded or that the workflow objective
succeeded.

Keep the original intent and outcome event immutable. Append a dedicated
failure-disposition audit containing the prior run/effect revisions, original
step hash, business key, dispatch evidence, expected-postcondition false proof,
undesired-result true proof, causal contract ID/version/hash, exact surface
identity, evidence references and observation times. Do not rewrite the
original `StepResult` as `VerificationState=verified`, create a verified
milestone for that step, or change its dispatch to `notDispatched`. The
reconciliation API should return a separate disposition such as
`verifiedUndesired`; `CommitConfirmed` may describe only the audit transaction.
The run remains stopped (`paused`) and attention-gated. Business status remains
unverified until an independent objective evaluator establishes it.
The separately designed guarded stopped-boundary transaction is still
required: a persisted `running` status and a failed Endly operation do not by
themselves prove quiescence. That boundary records truthful stopped execution;
it does not resolve the effect.

Generalize the host-selected reconciliation contract to return a typed outcome
classification, not a caller-selected boolean. The existing expected-outcome
contract continues to produce `confirmed` only on its true result. An
undesired-outcome contract must positively identify a bounded alternative
state and independently evaluate the expected postcondition as false. A false
expected predicate alone is insufficient: it does not identify what happened.

## Require causal qualification

An outcome is not causally verified merely because a request ID, attempt ID,
process, or timestamp correlates with a later observation. A contract for
`Cmd+Shift+G`, for example, must be qualified for that exact input, Chrome
profile/process, document or window, and the observed alternative UI. It must
use a trusted dispatch receipt plus fresh pre/post evidence or an equivalent
instrumented transition proof, establish no competing dispatch in the boundary,
and bind the same process birth, broker/channel epoch and authorized target
scope. An AX snapshot that happens to show Find after an input can remain
diagnostic evidence while causality is unqualified; the effect stays `unknown`.

## Repair without replay

Keep both `unknown` and `verifiedUndesired` as no-replay barriers for ordinary
resume. A causally verified undesired result may support compensation tied to
that effect. Causal verification is not a prerequisite for every safe recovery:
a separate host-qualified state repair may act on an independently observed
current UI condition while leaving the original effect `unknown`. For example,
a fresh, exact observation of a local Find panel may authorize clicking that
panel's unique Cancel control under an action-specific contract. This repairs
the present UI; it does not prove the shortcut caused the panel, that the
expected Go To Window action occurred, or that the original effect is absent.

Independent state repair requires a new narrow admission path. The current
`recovery.Context` and `recovery.Validate` reject unknown effects, and
`LoadResume` rejects unresolved effects; none supports this route. Do not relax
those guards or run the original workflow. Under a host-verified stopped
boundary, admit only a bounded intervention whose trusted contract binds the
fresh current-state evidence, exact principal, process/document/window identity,
allowed local action, objective constraints and finite budget. Require a
nonduplication proof: the repair must be a distinct action with its own unique
attempt and business key, the action-specific precondition must still hold at
dispatch, and its result must be independently checked. If its state changes
before dispatch, stop and reobserve. Record a separate repair/intervention
lineage referencing the observation and, when useful, the unresolved original
effect. Do not use that reference to update or settle the original effect.

Keep the original effect row and its unresolved barrier intact; record the
repair action as a separate effect with its own receipt and verification. If
that new action is uncertain, it creates its own barrier. Ordinary resume
remains blocked until the original effect is causally reconciled or an
authorized disposition route resolves it. A local UI cleanup does not make an
irreversible external action safe to repeat. Unknown payments, submissions,
installation or other external effects require authoritative reconciliation or
operator attention, not an inferred compensating action.

Extend the recovery snapshot with typed failure/intervention facts and trusted
evidence references only when the corresponding bounded route is implemented.
For compensation, a separately qualified contract must name the exact failed
effect, allowed compensation action, target scope, new business key,
postcondition, reconciliation predicate and finite repair budget.

Repair admission must preserve the original failed step and effect history,
while giving the compensation its own step, attempt, effect and business key.
It must not count the failed step as a completed-success prefix, fabricate its
output, or permit the same original action to be resubmitted. The repair
revision needs explicit lineage from the compensation to the `verifiedUndesired`
effect, and Endly must resume at the admitted compensation step only after the
generated repair commit and runtime guard confirm admission. If no qualified
compensation exists, keep the run paused for operator attention. A later
objective success still requires independent objective evidence.

## Required API and validation gates

Add a host-owned reconciliation classification path and generated atomic writer
projection for `verifiedUndesired`, then update state projection, resume and
recovery readers to preserve its no-replay meaning. Separately, add a narrow
state-repair admission/ledger path that can authorize a locally scoped
intervention from fresh current-state evidence while preserving any unknown
original effect. It must not impersonate `ReconcileEffect`, `recovery.Context`,
or `LoadResume`; those retain their current unresolved-effect barriers.
Ordinary `ReconcileEffect` remains success-only unless its trusted contract can
explicitly return the new classification. Test that a true expected predicate
confirms, a false expected predicate stays unknown, a causally qualified
alternate outcome commits only `verifiedUndesired`, and a correlated but
causally unqualified observation remains unknown. Also test independent repair
with an unresolved original, changed precondition before dispatch, distinct
repair identity/business key, stale scope/revisions, cancellation, duplicate
attempt rejection, separate repair lineage, and that the original UI action
never dispatches twice. Test that independent repair cannot unlock ordinary
resume or claim objective success.
