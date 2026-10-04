package durable

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/loadrun"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func reconciliationContextFixture(t *testing.T) (*loadrun.Run, EffectReconcileRequest, model.Predicate) {
	t.Helper()
	plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Surfaces = map[string]model.Surface{
		"fixture": {Kind: "native", BundleID: "com.example.Fixture"},
	}
	plan.Requires = &model.Requirements{Adapters: []string{"native"}}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{
		"case": {Kind: model.StringValue, String: "case-17"},
	}
	predicate := model.Predicate{
		Kind: "adapter", Adapter: "native", Name: "valueEquals",
		Scope: model.PredicateScope{SurfaceRef: "fixture"},
		Inputs: map[string]model.Value{
			"bundleID":  {Kind: model.StringValue, String: "com.example.Fixture"},
			"strategy":  {Kind: model.StringValue, String: "id"},
			"selector":  {Kind: model.StringValue, String: "result"},
			"attribute": {Kind: model.StringValue, String: "value"},
			"expected":  {Kind: model.StringValue, String: "saved"},
		},
		RequiredAuthority: "observational", TimeoutMs: 1000, FreshnessMs: 500,
	}
	plan.Steps[0].Effect.Reconcile = &predicate
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(struct {
		Plan   model.Plan             `json:"plan"`
		Inputs map[string]model.Value `json:"inputs"`
	}{Plan: *plan})
	if err != nil {
		t.Fatal(err)
	}
	contentJSON := string(content)
	contentHash := data.ReconcileEffectHash(content)
	original := integration.StepResult{DispatchState: "dispatched", VerificationState: "unknown"}
	evidence, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	evidenceJSON := string(evidence)
	const runID, planID, attemptID = "run-17", "plan-17", "attempt-17"
	effectID := key("effect", attemptID)
	run := &loadrun.Run{
		Id: pointer(runID), PlanId: pointer(planID), Revision: pointer(7), Status: pointer("paused"),
		Plan: &loadrun.PlanRevision{ContentJson: &contentJSON, ContentHash: &contentHash},
		Attempts: []*loadrun.Attempt{{
			Id: pointer(attemptID), RunId: pointer(runID), PlanId: pointer(planID), StepId: pointer(plan.Steps[0].ID),
		}},
		Effects: []*loadrun.Effect{{
			Id: pointer(effectID), AttemptId: pointer(attemptID), RunId: pointer(runID),
			Revision: pointer(3), State: pointer("unknown"),
			BusinessKey: pointer(`{"case":{"kind":"string","string":"case-17"}}`), EvidenceJson: &evidenceJSON,
		}},
		Events: []*loadrun.Event{{
			Id: pointer(key("outcome-event", attemptID)), AttemptId: pointer(attemptID), RunId: pointer(runID),
			Sequence: pointer(4), Kind: pointer("outcome"), PayloadJson: &evidenceJSON,
		}},
	}
	req := EffectReconcileRequest{
		RunID: runID, PlanID: planID, AttemptID: attemptID, EffectID: effectID,
		ExpectedRunRevision: 7, ExpectedEffectRevision: 3, RequestID: "reconcile-17",
	}
	return run, req, predicate
}

func TestReconciliationContextRequiresImmutableCorrelatedRecords(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*loadrun.Run, *EffectReconcileRequest)
	}{
		{"tampered plan content", func(run *loadrun.Run, _ *EffectReconcileRequest) {
			*run.Plan.ContentJson += " "
		}},
		{"wrong run identity", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Id = pointer("run-other") }},
		{"wrong plan identity", func(_ *loadrun.Run, req *EffectReconcileRequest) { req.PlanID = "plan-other" }},
		{"stale run revision", func(_ *loadrun.Run, req *EffectReconcileRequest) { req.ExpectedRunRevision++ }},
		{"wrong attempt plan", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Attempts[0].PlanId = pointer("other-plan") }},
		{"wrong attempt run", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Attempts[0].RunId = pointer("other-run") }},
		{"duplicate attempt", func(run *loadrun.Run, _ *EffectReconcileRequest) {
			run.Attempts = append(run.Attempts, run.Attempts[0])
		}},
		{"missing attempt", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Attempts = nil }},
		{"request points at another effect", func(_ *loadrun.Run, req *EffectReconcileRequest) { req.EffectID = "effect-other" }},
		{"wrong effect attempt", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Effects[0].AttemptId = pointer("attempt-other") }},
		{"wrong effect run", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Effects[0].RunId = pointer("run-other") }},
		{"stale effect revision", func(_ *loadrun.Run, req *EffectReconcileRequest) { req.ExpectedEffectRevision++ }},
		{"missing stored business key", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Effects[0].BusinessKey = nil }},
		{"duplicate effect", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Effects = append(run.Effects, run.Effects[0]) }},
		{"missing effect", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Effects = nil }},
		{"missing outcome event", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Events = nil }},
		{"duplicate outcome event", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Events = append(run.Events, run.Events[0]) }},
		{"outcome event payload differs", func(run *loadrun.Run, _ *EffectReconcileRequest) {
			run.Events[0].PayloadJson = pointer(`{"dispatchState":"notDispatched"}`)
		}},
		{"outcome event belongs to another run", func(run *loadrun.Run, _ *EffectReconcileRequest) {
			run.Events[0].RunId = pointer("run-other")
		}},
		{"outcome event lacks sequence", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Events[0].Sequence = nil }},
		{"outcome event attempt differs", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Events[0].AttemptId = pointer("attempt-other") }},
		{"outcome event kind differs", func(run *loadrun.Run, _ *EffectReconcileRequest) { run.Events[0].Kind = pointer("intent") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run, req, _ := reconciliationContextFixture(t)
			test.mutate(run, &req)
			if _, _, err := reconciliationContext(run, req); !errors.Is(err, ErrNeedsReconciliation) {
				t.Fatalf("expected reconciliation barrier, got %v", err)
			}
		})
	}
}

func TestReconciliationContextUsesOriginalPlanAndOutcome(t *testing.T) {
	run, req, predicate := reconciliationContextFixture(t)
	c, effect, err := reconciliationContext(run, req)
	if err != nil {
		t.Fatalf("valid immutable records rejected: %v", err)
	}
	if c.RunID != req.RunID || c.PlanID != req.PlanID || c.AttemptID != req.AttemptID || c.EffectID != req.EffectID {
		t.Fatalf("identity correlation lost: %+v", c)
	}
	if c.Step.ID != *run.Attempts[0].StepId || c.Step.Action != "element.press" || c.Step.Effect.Reconcile == nil || c.Step.Effect.Reconcile.Name != predicate.Name {
		t.Fatalf("step was not reconstructed from immutable plan: %+v", c.Step)
	}
	if effect != run.Effects[0] || c.BusinessKey != *effect.BusinessKey {
		t.Fatalf("effect/business key correlation lost: %+v %+v", c, effect)
	}
	if c.Original.DispatchState != "dispatched" || c.Original.VerificationState != "unknown" {
		t.Fatalf("original outcome not preserved: %+v", c.Original)
	}
	actualKey, err := effectBusinessKey(c.Plan, c.Step, c.Values)
	if err != nil || actualKey != c.BusinessKey {
		t.Fatalf("original typed business key mismatch: %q, %v", actualKey, err)
	}
	*effect.BusinessKey = `{"case":{"kind":"string","string":"case-18"}}`
	actualKey, err = effectBusinessKey(c.Plan, c.Step, c.Values)
	if err != nil || actualKey == *effect.BusinessKey {
		t.Fatalf("mismatched stored business key was not detectable: %q, %v", actualKey, err)
	}
}

func TestDeclaredReconciliationDoesNotInventMissingPredicate(t *testing.T) {
	run, req, _ := reconciliationContextFixture(t)
	c, _, err := reconciliationContext(run, req)
	if err != nil {
		t.Fatal(err)
	}
	c.Step.Effect.Reconcile = nil
	if _, err := DeclaredReconciliation(c); !errors.Is(err, ErrNeedsReconciliation) {
		t.Fatalf("missing declared predicate was invented: %v", err)
	}

	c.Step.Effect.Reconcile = &model.Predicate{Kind: "adapter", Adapter: "native", Name: "valueEquals", Scope: model.PredicateScope{SurfaceRef: "fixture"}, RequiredAuthority: "observational", TimeoutMs: 1000, FreshnessMs: 500}
	contract, err := DeclaredReconciliation(c)
	if err != nil {
		t.Fatalf("declared predicate rejected: %v", err)
	}
	if contract.ID != "plan.effect.reconcile" || contract.Version != "1" || contract.Predicate.Name != "valueEquals" || contract.Predicate.Scope.SurfaceRef != "fixture" {
		t.Fatalf("declared contract changed: %+v", contract)
	}
}
