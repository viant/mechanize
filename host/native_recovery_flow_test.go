package host

import (
	"context"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	repairs "github.com/viant/mechanize/engine/recovery"
	"github.com/viant/mechanize/model"
	core "github.com/viant/mechanize/recovery"
)

// Connect the real evidence provider to the real patch validator. Observation
// and qualification are explicit fixture providers, not a live app qualification.
func TestNativeRecoveryEvidenceSupportsScopedLocatorRepair(t *testing.T) {
	p, err := auth.NewPrincipal("fixture", "", "scoped-repair", []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID = "fixture-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	surface := model.Surface{Kind: "native", BundleID: "com.example.Report", ProcessID: 42, ProcessStartToken: "1790000000:1"}
	str := func(s string) model.Value { return model.Value{Kind: model.StringValue, String: s} }
	target := model.Selector{Surface: surface, Cardinality: "one", Scope: model.Scope{Window: map[string]model.Value{"title": str("Report")}}, Locator: &model.Locator{Strategy: "id", Value: str("old-save"), Exact: true}}
	predicate := &model.Predicate{Kind: "adapter", Adapter: "fixture", Name: "saved", Scope: model.PredicateScope{SurfaceRef: "report"}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "authoritative"}
	step := model.Step{ID: "save", Action: "element.press", Target: target, SemanticsProfile: "report.save.v1", TimeoutMs: 1000, Postcondition: predicate, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"record": str("fixture-record")}, Reconcile: predicate}}
	plan := model.Plan{SchemaVersion: 1, Steps: []model.Step{step}, Surfaces: map[string]model.Surface{"report": surface}, Objective: predicate, Constraints: &model.Constraints{AllowedApps: []string{surface.BundleID}}, Recovery: &model.RecoveryPolicy{MaxRepairs: 2, MaxElapsedMs: 10000, OnUnknownEffect: "needsAttention"}, Requires: &model.Requirements{Adapters: []string{"fixture"}, SemanticsProfiles: []string{step.SemanticsProfile}}}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	snapshot := repairs.Snapshot{Reference: repairs.RunReference{RunID: "run", PlanID: "plan", Revision: 3, Status: "paused", PlanHash: core.Hash(plan), ObjectiveHash: core.ObjectiveHash(plan)}, Plan: plan}
	policy := NativeRecoveryEvidencePolicy{PolicyHash: "reviewed-fixture-policy-v1", SafeNames: []string{"Report", "Save"}, SafeIdentifiers: []string{"old-save", "new-save"}, Contracts: []core.Contract{{Profile: step.SemanticsProfile, Action: step.Action, Surface: surface, Permissions: []string{"desktop:control"}, Qualified: true, TargetScope: &target, Postcondition: predicate, Reconcile: predicate}}}
	reads := 0
	provider, err := NewNativeRecoveryEvidence(NativeRecoveryEvidenceOptions{
		Resolve: func(context.Context, auth.Principal, repairs.Snapshot) (NativeRecoveryEvidencePolicy, error) {
			return policy, nil
		},
		Observe: func(context.Context, auth.Principal, model.Surface) (model.Observation, error) {
			reads++
			now := time.Now()
			return model.Observation{Surface: surface, Started: now.Add(-time.Millisecond), Ended: now, Nodes: []model.Node{
				{Ref: model.ElementRef{ID: "window"}, Role: "window", Name: "Report"},
				{Ref: model.ElementRef{ID: "button"}, ParentID: "window", Role: "button", Name: "Save", Identifier: "new-save"},
			}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := provider.Prepare(ctx, p, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Verify(ctx, p, snapshot, evidence); err != nil {
		t.Fatal(err)
	}
	if reads != 2 {
		t.Fatal("evidence was not independently observed again")
	}
	budget := core.Budget{MaxRepairs: 2, MaxElapsedMs: 10000}
	planning := core.RecoveryContext{Namespace: p.Namespace, Base: plan, ObjectiveHash: core.ObjectiveHash(plan), Contracts: evidence.Contracts, IncidentBudget: budget, WorkflowBudget: budget, Observation: evidence.Observation, EvidenceRefs: evidence.EvidenceRefs, Now: time.Now()}
	next := step
	next.Target.Locator = &model.Locator{Strategy: "id", Value: str("new-save"), Exact: true}
	patch := core.PlanPatch{BaseHash: core.Hash(plan), ObjectiveHash: core.ObjectiveHash(plan), RemainingSteps: []model.Step{next}, EvidenceRefs: evidence.EvidenceRefs}
	revision, err := core.Validate(ctx, planning, patch)
	if err != nil {
		t.Fatal(err)
	}
	if revision.ObjectiveHash != planning.ObjectiveHash || revision.Plan.Steps[0].Target.Locator.Value.String != "new-save" {
		t.Fatal("locator repair changed objective or lost target")
	}
	patch.RemainingSteps[0].Target.Scope.Window = map[string]model.Value{"title": str("Other report")}
	if _, err := core.Validate(ctx, planning, patch); err == nil {
		t.Fatal("same-process different-window repair accepted")
	}
}
