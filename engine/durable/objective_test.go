package durable

import (
	"context"
	"errors"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/mechanize/objective/fixture"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestEndlyDurableIndependentObjectiveOracle(t *testing.T) {
	for _, mode := range []string{"verified", "wrong-key", "offline", "unknown", "false", "observational-false", "no-objective"} {
		t.Run(mode, func(t *testing.T) {
			_, file, _, _ := runtime.Caller(0)
			p, _ := auth.NewPrincipal("fixture:issuer", "", "business-alice", []string{"desktop:control"})
			p.ClientID = "fixture-client"
			ctx := auth.WithPrincipal(context.Background(), p)
			store := fixture.New()
			businessKey := "case-1"
			if mode == "wrong-key" {
				businessKey = "case-2"
			}
			if mode != "unknown" {
				store.Put(p, fixture.Receipt{Reference: "independent-fixture-receipt", BusinessKey: businessKey, Completed: mode != "false" && mode != "observational-false", ObservedAt: time.Now()})
			}
			store.SetOffline(mode == "offline")
			enrollment := store.Enrollment()
			if mode == "observational-false" {
				enrollment.MaximumAuthority = objective.Observational
				enrollment.Adapter = completionAdapterFunc(func(c context.Context, p auth.Principal, name string, values map[string]model.Value) (objective.Result, error) {
					result, err := store.Evaluate(c, p, name, values)
					result.Authority = objective.Observational
					return result, err
				})
			}
			evaluator, err := objective.New(map[string]objective.Enrollment{"fixture-receipts": enrollment})
			if err != nil {
				t.Fatal(err)
			}
			var orchestrator *integration.Runtime
			b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), ObjectiveEvaluator: evaluator, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, StateMutationGuard: func(c context.Context, p auth.Principal, id string) (func(), error) {
				return orchestrator.StateMutationGuard(c, p, id)
			}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
				return integration.StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close(ctx)
			orchestrator, err = integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, run string, revision int, session, operation string) error {
				_, err := b.AttachOperation(ctx, p, run, revision, session, operation)
				return err
			}, CompleteObjective: b.CompleteObjective, EvaluatePostcondition: b.EvaluatePostcondition})
			if err != nil {
				t.Fatal(err)
			}
			session, err := orchestrator.Open(ctx, "objective fixture")
			if err != nil {
				t.Fatal(err)
			}
			plan, err := script.Compile(`app("com.example.Fixture").getById("status").read("value")`)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "no-objective" {
				plan.Requires = &model.Requirements{Adapters: []string{"fixture-receipts"}}
				plan.Surfaces = map[string]model.Surface{"fixture": {Kind: "native", BundleID: "com.example.Fixture"}}
				plan.Objective = &model.Predicate{Kind: "adapter", Adapter: "fixture-receipts", Name: "receiptCompleted", Scope: model.PredicateScope{SurfaceRef: "fixture"}, Inputs: map[string]model.Value{"businessKey": {Kind: model.StringValue, String: "case-1"}}, TimeoutMs: 30000, FreshnessMs: 30000, RequiredAuthority: "authoritative"}
			}
			if mode == "observational-false" {
				plan.Objective.RequiredAuthority = "observational"
			}
			op, err := orchestrator.StartPlan(ctx, session.SessionID, *plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			wait, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			if _, err = orchestrator.Wait(wait, session.SessionID, op.ID); err != nil {
				t.Fatal(err)
			}
			result, err := orchestrator.Result(ctx, session.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			want := "unverified"
			status := "paused"
			if mode == "verified" {
				want = "succeeded"
				status = "succeeded"
			}
			if mode == "false" {
				want = "failed"
				status = "failed"
			}
			if result.BusinessStatus != want {
				t.Fatalf("business status=%s want=%s reason=%s", result.BusinessStatus, want, result.Reason)
			}
			id, err := orchestrator.RunReference(ctx, session.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			state, err := b.StateGet(ctx, p, id)
			if err != nil {
				t.Fatal(err)
			}
			if state.Status != status {
				t.Fatalf("durable status=%s want=%s", state.Status, status)
			}
			if status == "paused" {
				if _, err = b.TransitionRun(ctx, p, id, state.Revision, "succeeded"); err == nil {
					t.Fatal("generic transition manufactured business success")
				}
			}
		})
	}
}

func TestUnverifiedEffectPostconditionStaysUnknownAndCannotReplay(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture:issuer", "", "effect-objective", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	evaluator, _ := objective.New(map[string]objective.Enrollment{"fixture-receipts": fixture.New().Enrollment()})
	calls := 0
	var captured context.Context
	b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), ObjectiveEvaluator: evaluator, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(c context.Context, _ auth.Principal, _ model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		calls++
		captured = c
		return integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	r, err := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, run string, revision int, session, operation string) error {
		_, err := b.AttachOperation(ctx, p, run, revision, session, operation)
		return err
	}, EvaluatePostcondition: b.EvaluatePostcondition, CompleteObjective: b.CompleteObjective})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "effect fixture")
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	plan.Surfaces = map[string]model.Surface{"fixture": {Kind: "native", BundleID: "com.example.Fixture"}}
	plan.Requires = &model.Requirements{Adapters: []string{"fixture-receipts"}}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"fixtureCase": {Kind: model.StringValue, String: "case-1"}}
	plan.Steps[0].Postcondition = &model.Predicate{Kind: "adapter", Adapter: "fixture-receipts", Name: "receiptCompleted", Scope: model.PredicateScope{SurfaceRef: "fixture"}, Inputs: map[string]model.Value{"businessKey": {Kind: model.StringValue, String: "missing-receipt"}}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "authoritative"}
	op, err := r.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 20*time.Second)
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
	business, err := r.Result(ctx, session.SessionID, op.ID)
	if err != nil || business.BusinessStatus != "unverified" || business.VerificationState != "unknown" || state.Status != "running" {
		t.Fatalf("uncertain postcondition terminalized run: %+v %+v %v", business, state, err)
	}
	if len(state.UnresolvedEffects) != 1 {
		t.Fatalf("oracle unknown did not preserve unresolved effect: %+v", state)
	}
	if _, err = b.Execute(context.WithoutCancel(captured), p, plan.Steps[0], nil); err != ErrNeedsReconciliation {
		t.Fatalf("unknown effect replay result=%v", err)
	}
	if calls != 1 {
		t.Fatalf("unknown replay dispatched %d times", calls)
	}
}

func TestExecutionFailurePreservesDurableRepairBoundary(t *testing.T) {
	for _, mode := range []string{"confirmed-prefix", "read-failure", "objective-unavailable", "objective-error", "unknown-effect", "cancelled", "cancelled-unknown"} {
		t.Run(mode, func(t *testing.T) {
			_, file, _, _ := runtime.Caller(0)
			p, _ := auth.NewPrincipal("fixture:issuer", "", "repair-"+mode, []string{"desktop:control"})
			p.ClientID = "fixture-client"
			ctx := auth.WithPrincipal(context.Background(), p)
			var orchestrator *integration.Runtime
			stopped := true
			mutations, reads := 0, 0
			started := make(chan struct{}, 1)
			var evaluator *objective.Evaluator
			if mode == "objective-error" {
				evaluator, _ = objective.New(map[string]objective.Enrollment{"fixture-receipts": {Adapter: completionAdapterFunc(func(context.Context, auth.Principal, string, map[string]model.Value) (objective.Result, error) {
					return objective.Result{Truth: objective.True, Authority: "invalid"}, nil
				}), MaximumAuthority: objective.Authoritative, AllowedPredicates: map[string]bool{"receiptCompleted": true}}})
			}
			b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), ObjectiveEvaluator: evaluator, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, StateMutationGuard: func(c context.Context, p auth.Principal, id string) (func(), error) {
				return orchestrator.StateMutationGuard(c, p, id)
			}}, func(c context.Context, _ auth.Principal, step model.Step, _ map[string]model.Value) (integration.StepResult, error) {
				meta, _ := integration.ExecutionFromContext(c)
				if step.Effect.Class != model.ReadOnly {
					mutations++
					if mode == "unknown-effect" {
						return integration.StepResult{DispatchState: "unknown", VerificationState: "unknown"}, errors.New("fixture receipt uncertain")
					}
					if mode == "cancelled-unknown" {
						started <- struct{}{}
						<-c.Done()
						return integration.StepResult{DispatchState: "unknown", VerificationState: "unknown"}, c.Err()
					}
					return integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
				}
				reads++
				if mode == "cancelled" {
					started <- struct{}{}
					<-c.Done()
					return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, c.Err()
				}
				if stopped && (mode == "confirmed-prefix" || mode == "read-failure") {
					return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, errors.New("fixture locator/read failed")
				}
				if mode == "confirmed-prefix" && meta.StepIndex != 1 {
					return integration.StepResult{}, errors.New("resume lost original step index")
				}
				return integration.StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close(ctx)
			orchestrator, err = integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, run string, revision int, session, operation string) error {
				_, err := b.AttachOperation(ctx, p, run, revision, session, operation)
				return err
			}, CompleteObjective: b.CompleteObjective, EvaluatePostcondition: b.EvaluatePostcondition, LoadResume: b.LoadResume, AttachOperation: func(c context.Context, p auth.Principal, run string, rev int, session, operation string) error {
				_, err := b.AttachResumedOperation(c, p, run, rev, session, operation)
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
			source := `app("com.example.Fixture").getById("status").read("value")`
			if mode == "confirmed-prefix" {
				source = "app(\"com.example.Fixture\").getById(\"save\").click()\n" + source
			}
			if mode == "unknown-effect" || mode == "cancelled-unknown" {
				source = `app("com.example.Fixture").getById("save").click()`
			}
			plan, err := script.Compile(source)
			if err != nil {
				t.Fatal(err)
			}
			for i := range plan.Steps {
				if plan.Steps[i].Effect.Class != model.ReadOnly {
					plan.Steps[i].Effect.BusinessKey = map[string]model.Value{"entity": {Kind: model.StringValue, String: "case-1"}}
				}
			}
			if mode == "objective-unavailable" || mode == "objective-error" {
				plan.Requires = &model.Requirements{Adapters: []string{"fixture-receipts"}}
				plan.Surfaces = map[string]model.Surface{"fixture": {Kind: "native", BundleID: "com.example.Fixture"}}
				plan.Objective = &model.Predicate{Kind: "adapter", Adapter: "fixture-receipts", Name: "receiptCompleted", Scope: model.PredicateScope{SurfaceRef: "fixture"}, Inputs: map[string]model.Value{"businessKey": {Kind: model.StringValue, String: "case-1"}}, TimeoutMs: 30000, FreshnessMs: 30000, RequiredAuthority: "authoritative"}
			}
			op, err := orchestrator.StartPlan(ctx, session.SessionID, *plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			wait, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			if mode == "cancelled" || mode == "cancelled-unknown" {
				select {
				case <-started:
				case <-wait.Done():
					t.Fatal("fixture never started")
				}
				if _, err = orchestrator.Cancel(ctx, session.SessionID, op.ID); err != nil {
					t.Fatal(err)
				}
			}
			finished, err := orchestrator.Wait(wait, session.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			business, err := orchestrator.Result(ctx, session.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			runID, err := orchestrator.RunReference(ctx, session.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			state, err := b.StateGet(ctx, p, runID)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown-effect" || mode == "cancelled-unknown" {
				wantBusiness := "unverified"
				if mode == "cancelled-unknown" {
					wantBusiness = "cancelled"
				}
				if business.BusinessStatus != wantBusiness || business.VerificationState != "unknown" || state.Status != "running" || len(state.UnresolvedEffects) != 1 {
					t.Fatalf("uncertainty terminalized or hidden: %+v %+v", business, state)
				}
				if _, err = orchestrator.ResumeInSession(ctx, p, session.SessionID, runID, state.Revision, state.PlanID, state.ObjectiveID); !errors.Is(err, ErrNeedsReconciliation) {
					t.Fatalf("unknown effect resumed: %v", err)
				}
				if mutations != 1 {
					t.Fatal("unknown effect replayed")
				}
				return
			}
			if mode == "cancelled" {
				if finished.Status != manager.OperationCancelled || business.BusinessStatus != "cancelled" || state.Status != "cancelled" {
					t.Fatalf("cancellation misreported: %+v %+v", business, state)
				}
				return
			}
			if state.Status != "paused" || business.BusinessStatus != "unverified" || business.VerificationState != "unknown" && mode != "confirmed-prefix" && mode != "read-failure" {
				t.Fatalf("safe repair boundary missing: %+v %+v", business, state)
			}
			if mode == "objective-unavailable" || mode == "objective-error" {
				return
			}
			if finished.Status != manager.OperationFailed || business.VerificationState != "unknown" || reads != 1 {
				t.Fatal("execution failure became business failure or automatic retry")
			}
			if mode == "confirmed-prefix" && (mutations != 1 || len(state.Progress) != 1) {
				t.Fatal("confirmed prefix lost")
			}
			stopped = false
			resumed, err := orchestrator.ResumeInSession(ctx, p, session.SessionID, runID, state.Revision, state.PlanID, state.ObjectiveID)
			if err != nil {
				t.Fatal(err)
			}
			finished, err = orchestrator.Wait(wait, session.SessionID, resumed.Operation.ID)
			if err != nil || finished.Status != manager.OperationSucceeded || reads != 2 {
				t.Fatalf("explicit safe resume failed: %+v %v", finished, err)
			}
			if mode == "confirmed-prefix" && mutations != 1 {
				t.Fatal("confirmed mutation replayed")
			}
		})
	}
}

type completionAdapterFunc func(context.Context, auth.Principal, string, map[string]model.Value) (objective.Result, error)

func (f completionAdapterFunc) Evaluate(c context.Context, p auth.Principal, name string, values map[string]model.Value) (objective.Result, error) {
	return f(c, p, name, values)
}

func TestDefinitiveBusinessFalseRequiresQualifiedEvidence(t *testing.T) {
	proof := objective.Result{Truth: objective.False, Authority: objective.Authoritative, ObservedAt: time.Now(), Evidence: []objective.Evidence{{Kind: "receipt", Reference: "receipt-1", BusinessKey: "case-1"}}}
	if !authoritativeBusinessFalse(proof, 30000) {
		t.Fatal("qualified business false rejected")
	}
	for _, mutate := range []func(*objective.Result){func(r *objective.Result) { r.Authority = objective.Observational }, func(r *objective.Result) { r.Evidence[0].BusinessKey = "" }, func(r *objective.Result) { r.ObservedAt = time.Now().Add(-time.Minute) }, func(r *objective.Result) { r.Truth = objective.Unknown }} {
		candidate := proof
		candidate.Evidence = append([]objective.Evidence(nil), proof.Evidence...)
		mutate(&candidate)
		if authoritativeBusinessFalse(candidate, 30000) {
			t.Fatal("unqualified false terminalized business run")
		}
	}
}
