package recovery

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
)

func fixture() (context.Context, RecoveryContext, PlanPatch) {
	p, _ := auth.NewPrincipal("issuer", "", "user", []string{"desktop"})
	surface := model.Surface{Kind: "native", BundleID: "fixture"}
	target := model.Selector{Surface: surface, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "submit"}, Exact: true}}
	predicate := &model.Predicate{Kind: "adapter", Adapter: "fixture", Name: "saved", Scope: model.PredicateScope{SurfaceRef: "app"}, TimeoutMs: 100, FreshnessMs: 100, RequiredAuthority: "authoritative"}
	step := model.Step{ID: "submit", Action: "element.press", Target: target, TimeoutMs: 100, SemanticsProfile: "qualified", Postcondition: predicate, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"case": {Kind: model.StringValue, String: "123"}}, Reconcile: predicate}}
	base := model.Plan{SchemaVersion: 1, Surfaces: map[string]model.Surface{"app": surface}, Objective: predicate, Constraints: &model.Constraints{AllowedApps: []string{"fixture"}}, Recovery: &model.RecoveryPolicy{MaxRepairs: 2, MaxElapsedMs: 1000, OnUnknownEffect: "needsAttention"}, Requires: &model.Requirements{SemanticsProfiles: []string{"qualified"}, Adapters: []string{"fixture"}}, Steps: []model.Step{step}}
	r := RecoveryContext{Namespace: p.Namespace, Base: base, ObjectiveHash: ObjectiveHash(base), Contracts: []Contract{{Profile: "qualified", Action: step.Action, Surface: surface, Permissions: []string{"desktop"}, Qualified: true, Postcondition: predicate, Reconcile: predicate}}, IncidentBudget: Budget{MaxRepairs: 1, MaxElapsedMs: 500}, WorkflowBudget: Budget{MaxRepairs: 2, MaxElapsedMs: 1000}, EvidenceRefs: []string{"evidence"}}
	patch := PlanPatch{BaseHash: Hash(base), ObjectiveHash: r.ObjectiveHash, RemainingSteps: []model.Step{step}, EvidenceRefs: []string{"evidence"}}
	return auth.WithPrincipal(context.Background(), p), r, patch
}
func TestChangedRoutePreservesObjective(t *testing.T) {
	ctx, r, p := fixture()
	p.RemainingSteps[0].Target.Locator = &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "new-submit"}, Exact: true}
	v, err := Validate(ctx, r, p)
	if err != nil {
		t.Fatal(err)
	}
	if v.ParentHash == v.Hash || v.ObjectiveHash != r.ObjectiveHash {
		t.Fatalf("bad revision %+v", v)
	}
	p.RemainingSteps[0].ID = "caller-edit"
	if v.Plan.Steps[0].ID == "caller-edit" {
		t.Fatal("revision aliases caller")
	}
}
func TestRejectUnsafePatch(t *testing.T) {
	for _, name := range []string{"objectiveTampering", "duplicateEffect", "unknownPolicy", "unknownEffect", "budget", "scope", "unqualified", "skippedEffect", "committedHistory"} {
		t.Run(name, func(t *testing.T) {
			ctx, r, p := fixture()
			switch name {
			case "objectiveTampering":
				p.ObjectiveHash = "tampered"
			case "duplicateEffect":
				r.Effects = []EffectRecord{{StepID: "previous", State: "committed", BusinessKey: r.Base.Steps[0].Effect.BusinessKey}}
			case "unknownPolicy":
				r.Base.Recovery.OnUnknownEffect = "retry"
				p.BaseHash = Hash(r.Base)
			case "unknownEffect":
				r.Effects = []EffectRecord{{StepID: "previous", State: "unknown"}}
			case "budget":
				r.IncidentBudget.UsedRepairs = 1
			case "scope":
				p.RemainingSteps[0].Target.Surface.BundleID = "other"
			case "unqualified":
				r.Contracts[0].Qualified = false
			case "skippedEffect":
				p.RemainingSteps[0].Action = "element.read"
				p.RemainingSteps[0].Effect = model.Effect{Class: model.ReadOnly}
				p.RemainingSteps[0].Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: "text"}}
			case "committedHistory":
				r.CompletedSteps = 1
			}
			if _, err := Validate(ctx, r, p); err == nil {
				t.Fatal("unsafe patch accepted")
			}
		})
	}
}

type countingProposer struct{ calls int }

func (p *countingProposer) Propose(context.Context, RecoveryContext) (PlanPatch, error) {
	p.calls++
	return PlanPatch{}, nil
}
func TestPlannerPreflightIsolationAndUnknownBarrier(t *testing.T) {
	ctx, r, _ := fixture()
	planner := &countingProposer{}
	r.Namespace = "other"
	if _, err := Propose(ctx, planner, r); err == nil || planner.calls != 0 {
		t.Fatal("cross-namespace planner was invoked")
	}
	ctx, r, _ = fixture()
	r.Effects = []EffectRecord{{State: "unknown"}}
	if _, err := Propose(ctx, planner, r); err == nil || planner.calls != 0 {
		t.Fatal("planner invoked across unknown-effect barrier")
	}
}
func TestDecodeRejectsExecutableOrTrailingContent(t *testing.T) {
	for _, data := range []string{`{"baseHash":"x","objectiveHash":"y","javascript":"tools.click()"}`, `{} {}`} {
		if _, err := DecodePatch([]byte(data)); err == nil {
			t.Fatal("untyped content accepted")
		}
	}
}
