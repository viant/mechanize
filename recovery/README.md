# Typed objective-preserving repair proposals

`Proposer.Propose` receives a bounded, cloned, already redacted read-only context;
no tool callbacks, handles, arbitrary code or planner-granted permissions exist.
Use `DecodePatch` at an external planner JSON boundary and `Propose` to bound calls.
The host must supply authentic adapter contracts, committed prefix, reconciliation
history and current bindings/dependency versions from its owned run state.

`Validate` checks verified namespace, base hash and every non-step objective field,
closed IR validation, scopes, exact qualified contracts, permissions, postconditions,
reconciliation predicates, resolved business keys, completed-prefix immutability,
remaining business effects and finite incident/workflow budgets. Any unknown effect
blocks repair until authoritative reconciliation. It returns a cloned new revision,
parent hash and first remaining step. It does not modify effect history or execute.

These are conservative contracts: changed navigation/selectors can preserve a remaining
business effect; skipping a remaining effect requires the host to reconcile and advance
the committed prefix first. Current shared IR conservatively classifies mutation actions
as externally consequential. There is no claim of adapter-backed risk lowering here.

Endly must resolve fresh unique targets, verify milestone dependencies and outcomes,
and consume budgets durably at admission. Datly components must CAS-persist the new
revision/provenance before execution. These packages provide no scheduler, persistence,
actual LLM transport, live platform qualification or automatic production readiness.
