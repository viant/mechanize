package durable

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/mechanize/script"
)

func TestGeneratedLateEffectReconciliationNeverReplaysAndPreservesAudit(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture:issuer", "", "late-effect", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	reads, dispatches, releases := 0, 0, 0
	value := "not-ready"
	adapter, _ := objective.NewNative(func(context.Context, auth.Principal, model.Selector, string) (model.Value, objective.NativeEvidence, error) {
		reads++
		return model.Value{Kind: model.StringValue, String: value}, objective.NativeEvidence{HelperEpoch: "qualified-read", TargetRef: "fresh-ref", ObservedAt: time.Now()}, nil
	})
	evaluator, _ := objective.New(map[string]objective.Enrollment{"native": adapter.Enrollment()})
	b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), ObjectiveEvaluator: evaluator, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, ReconciliationGuard: func(context.Context, auth.Principal, string) (func() error, error) {
		return func() error { releases++; return nil }, nil
	}, ResolveReconciliation: func(_ context.Context, _ auth.Principal, c ReconciliationContext) (ReconciliationContract, error) {
		return DeclaredReconciliation(c)
	}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		dispatches++
		return integration.StepResult{DispatchState: "dispatched", VerificationState: "unknown"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	r, err := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, run string, revision int, session, operation string) error {
		_, err := b.AttachOperation(ctx, p, run, revision, session, operation)
		return err
	}, CompleteObjective: b.CompleteObjective})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "late evidence fixture")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := script.Compile(`app("com.example.Fixture", processId: 42, processStartToken: "1790000000:1").getById("navigate", exact: true).click()`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Surfaces = map[string]model.Surface{"fixture": plan.Steps[0].Target.Surface}
	// Datly component materialization under -race is part of this fixture's
	// setup/execution budget; no native input deadline is relaxed in production.
	plan.Steps[0].TimeoutMs = 120000
	plan.Requires = &model.Requirements{Adapters: []string{"native"}}
	inputs := map[string]model.Value{}
	for k, v := range map[string]string{"bundleID": "com.example.Fixture", "processStartToken": "1790000000:1", "strategy": "id", "selector": "view", "attribute": "name", "expected": "ready"} {
		inputs[k] = model.Value{Kind: model.StringValue, String: v}
	}
	inputs["processId"] = model.Value{Kind: model.NumberValue, Number: 42}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"task": {Kind: model.StringValue, String: "fixture-navigation"}}
	plan.Steps[0].Effect.Reconcile = &model.Predicate{Kind: "adapter", Adapter: "native", Name: "valueEquals", Inputs: inputs, Scope: model.PredicateScope{SurfaceRef: "fixture"}, TimeoutMs: 30000, FreshnessMs: 30000, RequiredAuthority: "observational"}
	op, err := r.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	if _, err = r.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	runID, err := r.RunReference(ctx, session.SessionID, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := b.StateGet(ctx, p, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.UnresolvedEffects) != 1 {
		t.Fatalf("expected unknown effect: %+v", state)
	}
	effect := state.UnresolvedEffects[0]
	req := EffectReconcileRequest{RunID: runID, PlanID: state.PlanID, AttemptID: *effect.AttemptId, EffectID: *effect.Id, ExpectedRunRevision: state.Revision, ExpectedEffectRevision: *effect.Revision, RequestID: "readback-1"}
	unknown, err := b.ReconcileEffect(ctx, p, req)
	if err != nil || unknown.CommitConfirmed || unknown.State != "unknown" {
		bound, user, loadErr := b.bound(ctx, p, 0)
		if loadErr == nil {
			loaded, loadErr := load(bound, user.server, p, runID)
			if loadErr == nil {
				t.Logf("fixture state=%s revision=%d expected=%d plan=%s", *loaded.Status, *loaded.Revision, req.ExpectedRunRevision, *loaded.PlanId)
				for _, e := range loaded.Effects {
					t.Logf("fixture effect state=%v evidence=%v", e.State, e.EvidenceJson)
					if e.EvidenceJson != nil {
						t.Logf("fixture receipt %s", *e.EvidenceJson)
					}
				}
				for _, e := range loaded.Events {
					if e.Kind != nil {
						t.Logf("fixture audit kind=%s payload=%v", *e.Kind, e.PayloadJson)
					}
				}
			}
		}
		t.Fatalf("false promoted: %+v %v", unknown, err)
	}
	value = "ready"
	confirmed, err := b.ReconcileEffect(ctx, p, req)
	if err != nil {
		t.Fatal(err)
	}
	if !confirmed.CommitConfirmed || confirmed.Run.Status != "paused" || confirmed.Run.NeedsAttention || len(confirmed.Run.UnresolvedEffectIDs) != 0 || confirmed.Run.Revision != req.ExpectedRunRevision+1 {
		t.Fatalf("bad commit projection %+v", confirmed)
	}
	beforeReads := reads
	adopted, err := b.ReconcileEffect(ctx, p, req)
	if err != nil || !adopted.CommitConfirmed || reads != beforeReads || dispatches != 1 {
		t.Fatalf("lost response repeated work: %+v %v reads=%d dispatches=%d", adopted, err, reads, dispatches)
	}
	bound, user, err := b.bound(ctx, p, 0)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := load(bound, user.server, p, runID)
	if err != nil {
		t.Fatal(err)
	}
	original, late := 0, 0
	for _, event := range persisted.Events {
		if event.Kind == nil {
			continue
		}
		switch *event.Kind {
		case "outcome":
			original++
			var old integration.StepResult
			if json.Unmarshal([]byte(*event.PayloadJson), &old) != nil || old.VerificationState != "unknown" {
				t.Fatal("original receipt overwritten")
			}
		case "effect_reconciliation":
			late++
		}
	}
	if original != 1 || late != 1 || len(persisted.Milestones) != 1 || releases != 3 {
		t.Fatal("audit/milestone/release count mismatch")
	}
	snapshot, err := b.LoadResume(ctx, p, runID, confirmed.Run.Revision, state.PlanID, state.ObjectiveID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Completed) != 1 || dispatches != 1 {
		t.Fatal("reconciled step not adopted for skip")
	}
	wrong := req
	wrong.RequestID = "different-request"
	if _, err = b.ReconcileEffect(ctx, p, wrong); err == nil {
		t.Fatal("different stale request adopted previous commit")
	}
}
