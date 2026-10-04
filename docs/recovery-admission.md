# Recovery admission and explicit resume

Recovery preserves the original business objective, constraints, input values,
business keys and completed effects. A proposed replacement route is a new
immutable plan revision. Endly executes it only after a separate explicit resume.

Both `mechanize_recovery_context` and `mechanize_recovery_admit` require the live
owned `sessionId` and a bounded `purpose`, in addition to exact `runId`,
`expectedRevision`, and `expectedPlanId`. Admission also takes the closed `patch`
object. Caller-supplied grants, namespace overrides, qualification flags and
quiescence proofs are rejected. Session ownership supplies a consent context;
it does not itself grant desktop access.

Unknown effects must first be reconciled. Recording a stopped boundary does not
remove that requirement. A current paused state, matching objective hashes and
available repair budget are also necessary.

Before admitting a new revision, the host acquires the stopped Endly/native
executor guard and reads the exact durable boundary again. It prepares the fixed
Datly writer before collecting fresh evidence, so cold compilation does not
consume the short evidence lifetime. It then checks trusted observations,
qualified action contracts, preserved effects and scope, and finite incident and
workflow budgets. The generated transaction records the plan, lineage, audit and
budget reservation atomically.

`commitConfirmed` reports storage evidence. `readyToResume` additionally requires
the guarded current revision and runtime readiness. If state readback or guard
cleanup fails after a confirmed write, the response retains the repair reference
and commit information, clears readiness, and requires attention. An error does
not establish rollback. Retrying the exact original admission can adopt its
immutable record, but must reacquire the guard and recheck state before reporting
readiness; it cannot consume another budget or replay input.

## Current implementation boundary

The host guard qualifies native plans only. Chrome and mixed routes need a
matching browser executor guard. The source now includes a native evidence
provider wired through the trusted `HostOptions.NativeRecoveryPolicy` callback.
The default server has no recovery-policy enrollment, so it continues returning
`needsAttention` until a deployment supplies separately qualified contracts.
Advertised Accessibility actions and capability flags are not qualification
evidence. Synthetic test profiles are not automatically enrolled for employees'
applications.

The native provider binds exact process identity and scope, withholds values and
raw element handles, permits only explicitly allowlisted display labels, and
independently refreshes policy and observations. Stable evidence references bind
the owned revision, trusted policy, visible semantics and private UI topology;
refreshed opaque handles alone do not invalidate them. A changed hierarchy, process
or policy invalidates the proof. Incomplete or stale observations are rejected.

`Contract.TargetScope` marks a locator-only qualification. It retains every
selector field except the leaf locator, including window, ancestors, process,
frame/tab boundaries, cardinality and ordering. The native provider requires
this explicit restriction and matches each contract against an original
remaining step. It does not promote advertised Accessibility actions into
qualified routes.

The trusted resolver must return deployment-owned contract metadata and explicit
safe-name/identifier allowlists. It cannot come from workflow JSON or MCP input.
It runs while the native execution fence is held during admission and must not
acquire input or dispatch actions. Observations continue through the host's
ordinary authorization and consent path. App/version qualification, measured
reliability, and a live changed-screen repair remain acceptance gates; fake
observation-provider tests do not establish those outcomes.
