package durable

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	repairs "github.com/viant/mechanize/engine/recovery"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	core "github.com/viant/mechanize/recovery"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestStatePatchWithVerifiedRepairLineagePreservesLedger(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "state-lineage-alice", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	_, file, _, _ := runtime.Caller(0)
	surface := model.Surface{Kind: "native", BundleID: "fixture.editor"}
	predicate := &model.Predicate{Kind: "adapter", Adapter: "fixture", Name: "saved", Scope: model.PredicateScope{SurfaceRef: "app"}, Inputs: map[string]model.Value{"businessKey": {Kind: model.ReferenceValue, Ref: "input.case"}}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "authoritative"}
	step := func(id string) model.Step {
		return model.Step{ID: id, Action: "element.press", Target: model.Selector{Surface: surface, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "old-button"}, Exact: true}}, TimeoutMs: 1000, SemanticsProfile: id + ".v1", Postcondition: predicate, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"case": {Kind: model.ReferenceValue, Ref: "binding.alias"}, "phase": {Kind: model.StringValue, String: id}}, Reconcile: predicate}}
	}
	plan := model.Plan{SchemaVersion: 1, Inputs: map[string]model.InputDefinition{"case": {Type: model.StringValue, Required: true}}, Surfaces: map[string]model.Surface{"app": surface}, Requires: &model.Requirements{Adapters: []string{"fixture"}, SemanticsProfiles: []string{"save.v1", "finish.v1"}}, Objective: predicate, Constraints: &model.Constraints{AllowedApps: []string{surface.BundleID}}, Recovery: &model.RecoveryPolicy{MaxRepairs: 2, MaxElapsedMs: 300000, OnUnknownEffect: "needsAttention"}, Steps: []model.Step{step("save"), step("finish")}}
	entity := model.Value{Kind: model.ReferenceValue, Ref: "input.case"}
	alias := model.Value{Kind: model.ReferenceValue, Ref: "binding.entity"}
	free := model.Value{Kind: model.StringValue, String: "initial"}
	plan.Bindings = []model.Binding{{Name: "entity", Type: "value", Value: &entity}, {Name: "alias", Type: "value", Value: &alias}, {Name: "summary", Type: "value", Value: &free}}
	guardHeld, refreshes := false, 0
	evaluator, err := objective.New(map[string]objective.Enrollment{"fixture": {Adapter: lineageOracle{}, MaximumAuthority: objective.Authoritative, BusinessKeyInput: "businessKey", AllowedPredicates: map[string]bool{"saved": true}}})
	if err != nil {
		t.Fatal(err)
	}
	var orchestrator *integration.Runtime
	saves, finishes := 0, 0
	store, err := New(Options{SourceRoot: filepath.Dir(filepath.Dir(filepath.Dir(file))), StorageRoot: t.TempDir(), ObjectiveEvaluator: evaluator, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, StateMutationGuard: func(ctx context.Context, p auth.Principal, id string) (func(), error) {
		release, err := orchestrator.StateMutationGuard(ctx, p, id)
		if err != nil {
			return nil, err
		}
		guardHeld = true
		return func() { guardHeld = false; release() }, nil
	}}, func(_ context.Context, _ auth.Principal, s model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		if s.ID == "save" {
			saves++
			return integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
		}
		if s.Target.Locator.Value.String != "changed-button" {
			return integration.StepResult{DispatchState: "notDispatched"}, errors.New("fixture target changed")
		}
		finishes++
		return integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close(ctx)
	orchestrator, err = integration.NewWithOptions(store.Execute, integration.Options{PreparePlan: store.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, id string, rev int, session, operation string) error {
		_, err := store.AttachOperation(ctx, p, id, rev, session, operation)
		return err
	}, EvaluatePostcondition: store.EvaluatePostcondition, CompleteObjective: store.CompleteObjective, LoadResume: store.LoadResume, AttachOperation: func(ctx context.Context, p auth.Principal, id string, rev int, session, operation string) error {
		_, err := store.AttachResumedOperation(ctx, p, id, rev, session, operation)
		return err
	}})
	if err != nil {
		t.Fatal(err)
	}
	store.options.RefreshVariables = func(c context.Context, actor auth.Principal, id string, values map[string]model.Value) error {
		if !guardHeld || values["summary"].String == "" {
			return errors.New("refresh missed held admission or committed values")
		}
		refreshes++
		return orchestrator.RefreshVariables(c, actor, id, values)
	}
	session, err := orchestrator.Open(ctx, "repair fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer orchestrator.Close(ctx, session.SessionID)
	op, err := orchestrator.StartPlan(ctx, session.SessionID, plan, map[string]model.Value{"case": {Kind: model.StringValue, String: "case-1"}})
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if _, err = orchestrator.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	runID, err := orchestrator.RunReference(ctx, session.SessionID, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	service, err := repairs.New(repairs.Options{Invoke: store.InvokePrivateComponent, Authorize: func(_ context.Context, actual auth.Principal, s model.Surface) error {
		if actual.Namespace != p.Namespace || s != (model.Surface{}) && s != surface {
			return auth.ErrUnauthorized
		}
		return nil
	}, Guard: func(ctx context.Context, p auth.Principal, r repairs.RunReference) (func() error, error) {
		release, err := orchestrator.StateMutationGuard(ctx, p, r.RunID)
		if err != nil {
			return nil, err
		}
		return func() error { release(); return nil }, nil
	}, RuntimeReady: func(context.Context, auth.Principal) error { return nil }, PrepareEvidence: func(_ context.Context, _ auth.Principal, _ repairs.Snapshot) (repairs.Evidence, error) {
		now := time.Now()
		return repairs.Evidence{Verified: true, Redacted: true, PolicyHash: "fixture-policy", ValidUntil: now.Add(4 * time.Second), Observation: model.Observation{Surface: surface, Started: now, Ended: now}, EvidenceRefs: []string{"fixture:redacted-observation"}, Contracts: []core.Contract{{Qualified: true, Profile: "finish.v1", Action: "element.press", Surface: surface, Permissions: []string{"desktop:control"}, Postcondition: predicate, Reconcile: predicate}}}, nil
	}, VerifyEvidence: func(_ context.Context, _ auth.Principal, _ repairs.Snapshot, e repairs.Evidence) error {
		if !e.Verified || time.Now().After(e.ValidUntil) {
			return errors.New("stale fixture evidence")
		}
		return nil
	}, IncidentMaxRepairs: 2, IncidentMaxElapsedMs: 60000})
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.StateGet(ctx, p, runID)
	if err != nil {
		t.Fatal(err)
	}
	state, err = store.StatePatch(ctx, p, runID, state.Revision, map[string]model.Value{"summary": {Kind: model.StringValue, String: "before-repair"}})
	if err != nil || refreshes != 1 || guardHeld || state.Variables["summary"].String != "before-repair" {
		t.Fatalf("old absent+confirmed history blocked guarded patch: %+v %v", state, err)
	}
	beforeRevision := state.Revision
	for _, name := range []string{"entity", "alias"} {
		if _, err = store.StatePatch(ctx, p, runID, beforeRevision, map[string]model.Value{name: {Kind: model.StringValue, String: "case-2"}}); err == nil {
			t.Fatalf("confirmed dependency %s patched", name)
		}
	}
	state, err = store.StateGet(ctx, p, runID)
	if err != nil || state.Revision != beforeRevision || refreshes != 1 {
		t.Fatalf("rejected dependency patch changed old state: %+v %v", state, err)
	}
	before, err := service.Snapshot(ctx, p, runID)
	if err != nil {
		t.Fatal(err)
	}
	if before.CompletedSteps != 1 || before.Reference.Status != "paused" || saves != 1 || finishes != 0 {
		t.Fatalf("baseline not safely paused: %+v saves%d finishes%d", before.Reference, saves, finishes)
	}
	replacement := plan.Steps[1]
	replacement.Target.Locator = &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "changed-button"}, Exact: true}
	patch := core.PlanPatch{BaseHash: before.Reference.PlanHash, ObjectiveHash: before.Reference.ObjectiveHash, RemainingSteps: []model.Step{replacement}, EvidenceRefs: []string{"fixture:redacted-observation"}}
	body, _ := json.Marshal(patch)
	admitted, err := service.Admit(ctx, p, repairs.AdmissionRequest{ContextRequest: repairs.ContextRequest{RunID: runID, ExpectedPlanID: before.Reference.PlanID, ExpectedRevision: before.Reference.Revision}, Patch: body})
	if err != nil || !admitted.CommitConfirmed || !admitted.ReadyToResume {
		t.Fatalf("admit %+v %v", admitted, err)
	}
	after, err := service.Snapshot(ctx, p, runID)
	if err != nil {
		t.Fatal(err)
	}
	state, err = store.StateGet(ctx, p, runID)
	if err != nil {
		t.Fatal(err)
	}
	inheritedRevision := state.Revision
	for _, name := range []string{"entity", "alias"} {
		if _, err = store.StatePatch(ctx, p, runID, inheritedRevision, map[string]model.Value{name: {Kind: model.StringValue, String: "case-2"}}); err == nil {
			t.Fatalf("inherited confirmed dependency %s patched", name)
		}
	}
	state, err = store.StateGet(ctx, p, runID)
	if err != nil || state.Revision != inheritedRevision || refreshes != 1 {
		t.Fatalf("rejected inherited patch changed state: %+v %v", state, err)
	}
	state, err = store.StatePatch(ctx, p, runID, inheritedRevision, map[string]model.Value{"summary": {Kind: model.StringValue, String: "after-repair"}})
	if err != nil || refreshes != 2 || guardHeld || state.Revision != inheritedRevision+1 || state.Variables["summary"].String != "after-repair" {
		t.Fatalf("verified lineage unrelated patch failed: %+v %v", state, err)
	}
	preserved, err := service.Snapshot(ctx, p, runID)
	if err != nil || preserved.CompletedSteps != 1 || len(preserved.Raw.Attempts) != 2 || len(preserved.Raw.Effects) != 2 || saves != 1 || finishes != 0 {
		t.Fatalf("patch replayed or cleared history: %+v %v", preserved.Reference, err)
	}
	for _, attempt := range preserved.Raw.Attempts {
		if *attempt.PlanId != before.Reference.PlanID {
			t.Fatal("state validation relabelled ancestor attempt")
		}
	}
	for _, entry := range preserved.Lineage {
		if entry.OriginalPlanID != before.Reference.PlanID {
			t.Fatal("state validation lost original lineage")
		}
	}
	if after.Reference.PlanID == before.Reference.PlanID {
		t.Fatal("fixture did not exercise admitted repair ancestry")
	}
}
