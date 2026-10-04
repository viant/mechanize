# Durable repair admission

This package validates and persists repair admission; it does not execute a
workflow, call a model endpoint, invoke arbitrary tools, or add a scheduler.
Endly remains the executor. Root host/runtime wiring owns explicit resume after
verified admission under the same immutable run/objective identity.

`Snapshot(ctx, principal, runID)` is a private host/runtime API. It calls the
namespace-bound generated `LoadRecovery` component and verifies stored envelope
hashes, exact inputs/non-step objective lineage, original attempts/effects,
strict persisted notDispatched absence, confirmed milestone evidence and keys
at their original binding boundary. Completed effects must form a contiguous
prefix. It returns current/parent references and explicit original-plan lineage;
it never relabels old attempts or pretends they were dispatched by the new plan.
Raw Snapshot plan/input/value/ledger fields must not be exposed through MCP or
sent to a planner.

`Context` produces a bounded read-only redacted planning view with opaque exact
original hashes. Current binding/input/result values, helper handles/epochs and
node values are excluded. Sensitive defaults are removed from the planning view;
a legacy literal known secret in protected plan fields stops planning. Trusted
observation callbacks must independently redact display names and other source
metadata. The redacted view is not the original hash-bearing plan; proposals use
its separately supplied original base/objective hashes.

Trusted fresh observation/contracts/evidence and independent evidence checks
are required. Missing callbacks default to needsAttention. Callers cannot provide
qualification, observation authority, incident policy, budget counters or runtime
readiness. Unknown effects block evidence/planning/admission until a separate
qualified durable reconciliation path proves them. A single absent-looking UI
read is not sufficient absence evidence.

`Admit` decodes one strict closed PlanPatch and calls the existing neutral
`recovery.Validate`. It also preserves remaining business-effect input arguments.
After rechecking stopped runtime, all surface ceilings and fresh trusted evidence,
it consumes one incident/workflow repair and reserves the proposed route's full
bounded timeout cost before resume. Stable incident identity derives from the
owned run/objective and remaining business key, not a caller-chosen reset key.
The immutable new plan retains original input values and every non-step field.

One generated PATCH graph inserts the new immutable plan, repair provenance,
original ledger lineage and audit, updates both finite CAS budgets, and changes
the stopped run's plan/revision atomically. All product SQL is in authoritative
DQL/adjacent assets; there is no DAO or direct SQL fallback. An initial graph with
new plan beneath writable run was cyclic because native ordering makes children
depend on parents while the run's new FK depends on the plan. Correct authoring
uses an owned verified milestone as a nonmutating anchor, with the new plan and
existing run as siblings. The auxiliary milestone table is distinct from all
writable tables. Empty/no-milestone and unjournaled readonly-prefix admission
remain unsupported and require attention, rather than invented completion proof.

The admission permit is detached host context after validation; transport fields
cannot bind it. Raw namespace ingress is checked before native parent relation
producers can normalize foreign claims. The writer rechecks exact parent/run CAS,
stopped state, unresolved ledger state, immutable plan/lineage/audit and monotonic
budget policy/counts inside its managed transaction.

A failed or lost commit acknowledgement retains the exact repair reference and
needsAttention. Only a later generated read confirming the exact immutable
admission and current paused revision can enable explicit resume. Replays do not
consume another repair or rewrite history. RuntimeReady/Guard bindings must be
implemented before ready-to-resume is claimed; storage success alone is not
executable recovery evidence.

Exact admission replay acquires the stopped runtime guard and reloads the current
revision before checking readiness. Guard cleanup errors retain the confirmed
commit and immutable reference but clear readiness and report needsAttention.
An acknowledged commit remains confirmed if subsequent lineage readback fails.

Fixture evidence: redaction/default trust/unknown barriers; missing readonly
prefix refusal; held-out locator and extra-dialog inspection proposals; changed
objective/key/skipped effects/qualification/budget rejection; actual generated
SQLite atomic admission, original ledger identity preservation across two repair
plans, stale CAS, finite incident/workflow exhaustion, and committed reply-loss
reconciliation. SQL is used only for fixture setup, with product admission and
assertion reads through generated components. Synthetic fixture contracts are not
production reliability or native qualification. Root host/runtime fixture also proves Admit -> Builder.LoadResume -> same-owned
Endly.Resume: inherited confirmed prefix is skipped, the repaired locator executes
its remaining effect once, original/new attempt identities remain intact, and an
independent fixture objective succeeds. Signed/live platform qualification and
production recovery cohorts remain separate acceptance gates.
