package durable

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	repairs "github.com/viant/mechanize/engine/recovery"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	core "github.com/viant/mechanize/recovery"
)

type lineageOracle struct{}

func (lineageOracle) Evaluate(_ context.Context, _ auth.Principal, _ string, inputs map[string]model.Value) (objective.Result, error) {
	return objective.Result{Truth: objective.True, Authority: objective.Authoritative, ObservedAt: time.Now(), Evidence: []objective.Evidence{{Kind: "fixtureReceipt", Reference: "fixture:independent-receipt", BusinessKey: inputs["businessKey"].String}}}, nil
}

func TestAdmittedRepairResumesThroughEndlyWithoutRelabellingLedger(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "lineage-alice", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	_, file, _, _ := runtime.Caller(0)
	surface := model.Surface{Kind: "native", BundleID: "fixture.editor"}
	predicate := &model.Predicate{Kind: "adapter", Adapter: "fixture", Name: "saved", Scope: model.PredicateScope{SurfaceRef: "app"}, Inputs: map[string]model.Value{"businessKey": {Kind: model.ReferenceValue, Ref: "input.case"}}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "authoritative"}
	step := func(id string) model.Step {
		return model.Step{ID: id, Action: "element.press", Target: model.Selector{Surface: surface, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "old-button"}, Exact: true}}, TimeoutMs: 1000, SemanticsProfile: id + ".v1", Postcondition: predicate, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"case": {Kind: model.ReferenceValue, Ref: "input.case"}, "phase": {Kind: model.StringValue, String: id}}, Reconcile: predicate}}
	}
	plan := model.Plan{SchemaVersion: 1, Inputs: map[string]model.InputDefinition{"case": {Type: model.StringValue, Required: true}}, Surfaces: map[string]model.Surface{"app": surface}, Requires: &model.Requirements{Adapters: []string{"fixture"}, SemanticsProfiles: []string{"save.v1", "finish.v1"}}, Objective: predicate, Constraints: &model.Constraints{AllowedApps: []string{surface.BundleID}}, Recovery: &model.RecoveryPolicy{MaxRepairs: 2, MaxElapsedMs: 300000, OnUnknownEffect: "needsAttention"}, Steps: []model.Step{step("save"), step("finish")}}
	evaluator, err := objective.New(map[string]objective.Enrollment{"fixture": {Adapter: lineageOracle{}, MaximumAuthority: objective.Authoritative, BusinessKeyInput: "businessKey", AllowedPredicates: map[string]bool{"saved": true}}})
	if err != nil {
		t.Fatal(err)
	}
	var orchestrator *integration.Runtime
	saves, finishes := 0, 0
	store, err := New(Options{SourceRoot: filepath.Dir(filepath.Dir(filepath.Dir(file))), StorageRoot: t.TempDir(), ObjectiveEvaluator: evaluator, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, StateMutationGuard: func(ctx context.Context, p auth.Principal, id string) (func(), error) {
		return orchestrator.StateMutationGuard(ctx, p, id)
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
	orchestrator, err = integration.NewWithOptions(store.Execute, integration.Options{PreparePlan: store.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, run string, revision int, session, operation string) error {
		_, err := store.AttachOperation(ctx, p, run, revision, session, operation)
		return err
	}, EvaluatePostcondition: store.EvaluatePostcondition, CompleteObjective: store.CompleteObjective, LoadResume: store.LoadResume, AttachOperation: func(ctx context.Context, p auth.Principal, id string, rev int, session, operation string) error {
		_, err := store.AttachResumedOperation(ctx, p, id, rev, session, operation)
		return err
	}})
	if err != nil {
		t.Fatal(err)
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
	resumed, err := orchestrator.ResumeInSession(ctx, p, session.SessionID, runID, after.Reference.Revision, after.Reference.PlanID, after.Reference.ObjectiveID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = orchestrator.Wait(wait, session.SessionID, resumed.Operation.ID); err != nil {
		t.Fatal(err)
	}
	result, err := orchestrator.Result(ctx, session.SessionID, resumed.Operation.ID)
	if err != nil || result.BusinessStatus != "succeeded" || saves != 1 || finishes != 1 {
		t.Fatalf("repaired outcome %+v saves%d finishes%d %v", result, saves, finishes, err)
	}
	final, err := service.Snapshot(ctx, p, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Raw.Attempts) != 3 || *final.Raw.Attempts[0].PlanId == after.Reference.PlanID && *final.Raw.Attempts[1].PlanId == after.Reference.PlanID {
		t.Fatal("original attempts relabelled or repair effect missing")
	}
}
