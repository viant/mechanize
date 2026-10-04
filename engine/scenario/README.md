# Persisted reusable scenario proposals

`Service` invokes private generated Datly v1 `PublishScenarioDraft` and
`ListScenarios` components through the durable namespace-bound invocation bridge.
It owns no SQL, DAO, server pool or execution scheduler. Endly remains the only
execution scheduler, and selection returns a detached plan plus its immutable
scenario reference for a later explicit run. Scenario ID/revision/hash are
separate from a run's plan ID and objective ID.

`PublishDraft` accepts a typed plan, a recording ID, symbolic entity constraints
and exact declared requirements. Revision keys are immutable: exact canonical
replay succeeds; changed content under the same key conflicts. Unknown commit
acknowledgements are reconciled with an exact scoped generated read; unreadable
state remains unconfirmed. `publicationConfirmed` reports this separately from
the prospective draft reference.

Canonical schema version 1 forbids input defaults, literal business/mutation
values, command strings, captured target names/text, filesystem roots, structured
runtime objects, live run/artifact references, and literal captured window/frame scopes. Business
entity constraints and content arguments refer to declared `input.*` symbols;
current input values are never persisted by selection. Stable structural
role/identifier selectors remain typed IR. A configured provenance verifier
must independently establish their relation to the owned recording and its
review; syntax alone does not prove that a demonstration excludes every secret.

Web tab IDs are removed only when an explicit stable origin exists. Every
removed field is reported in `PublishResult.normalizedFields`; the returned
hash describes the normalized reusable definition. Captured title identity and
origins carrying paths, credentials, query parameters or fragments are rejected.
No objective/surface change is hidden. Original caller-owned plans are detached
before normalization.

`List` returns bounded compact draft summaries without plans, live input values
or arbitrary namespace controls. It supports exact ID/revision/objective hash
filters and keyset pagination via `next`/`after`. The connected Datly runtime
projection parser rejects a bound SQL LIMIT, so generated source uses literal
LIMIT 101 and the typed service slices each requested page after scoped invocation;
all product queries still belong to the generated reader. All declared, step, ancestor, predicate and binding surfaces are authorized
before publication or returning each summary/proposal; namespace comes exclusively from authenticated context.

`Select` accepts desired objective/entity/input schema/input values and a stable
surface, with optional exact scenario ID/revision. Requirements declarations are
not environment facts or qualification. Current environment and exact-reference
cohort evidence come only from configured trusted callbacks. Environment must be
verified and fresh; provenance is independently reverified before qualification.
Mixed native/web plans require trusted environment coverage for every secondary
surface as well as the primary requirements. Profile/version/cohort declarations
must describe the combined environment; primary-only evidence cannot qualify a
mixed plan. The selector compares exact objective/entity/schema/surface/profile/version/
verification/cohort, capabilities and principal permissions. Missing enrollment,
unknown/unmeasured qualification, unresolved recording gaps/issues, stale
observation, mismatches or ambiguity do not propose an executable plan.

No environment/provenance/qualification callbacks means drafts can be published
and listed, while selection returns `needsAttention`. Caller `reviewed` and gap
review claims do not establish trust. A selected result is always `proposalOnly`;
it grants no session, consent, input permission, retries, repairs or execution.
Callbacks receive detached data so they cannot mutate a plan returned under its
stored hash or change the verified environment used for selection.

Validation: generated SQLite fixtures prove composite revision keys, exact
replay/conflict, namespace isolation, canonical hash rejection, keyset pagination
and process restart. Separate injected component fixtures exercise unknown commit
acknowledgements and trusted callback boundaries. Trial numbers in those fixtures
are synthetic test data, not production reliability evidence.
