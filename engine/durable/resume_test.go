package durable

import (
	"context"
	"errors"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestGeneratedDatlyResumeReconstructsEndlyAndSkipsConfirmed(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture:issuer", "", "resume-alice", []string{"desktop:control"})
	ctx := auth.WithPrincipal(context.Background(), p)
	mutations := 0
	stopped := true
	dispatch := func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (integration.StepResult, error) {
		metadata, _ := integration.ExecutionFromContext(ctx)
		if step.Effect.Class != model.ReadOnly {
			mutations++
			return integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
		}
		if stopped {
			return integration.StepResult{}, errors.New("fixture process stopped")
		}
		if metadata.StepIndex != 1 {
			return integration.StepResult{}, errors.New("original index lost")
		}
		return integration.StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
	}
	options := Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}
	b, err := New(options, dispatch)
	if err != nil {
		t.Fatal(err)
	}
	r, err := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := script.Compile("app(\"com.example.Fixture\").getById(\"save\").click()\napp(\"com.example.Fixture\").getById(\"status\").read(\"value\")")
	if err != nil {
		t.Fatal(err)
	}
	entity := model.Value{Kind: model.StringValue, String: "case-1"}
	alias := model.Value{Kind: model.ReferenceValue, Ref: "binding.entity"}
	chain := model.Value{Kind: model.ReferenceValue, Ref: "binding.alias"}
	free := model.Value{Kind: model.StringValue, String: "initial"}
	plan.Bindings = append(plan.Bindings, model.Binding{Name: "entity", Type: "value", Value: &entity}, model.Binding{Name: "alias", Type: "value", Value: &alias}, model.Binding{Name: "chain", Type: "value", Value: &chain}, model.Binding{Name: "summary", Type: "value", Value: &free})
	for i := range plan.Steps {
		if plan.Steps[i].Effect.Class == model.ExternalNonIdempotent {
			plan.Steps[i].Effect.BusinessKey = map[string]model.Value{"fixtureCase": {Kind: model.ReferenceValue, Ref: "binding.chain"}}
		}
	}
	op, err := r.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	done, err := r.Wait(wait, session.SessionID, op.ID)
	if err != nil || done.Status != manager.OperationFailed {
		t.Fatalf("expected stopped fixture: %+v %v", done, err)
	}
	runID, err := r.RunReference(ctx, session.SessionID, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := b.StateGet(ctx, p, runID)
	if err != nil {
		t.Fatal(err)
	}
	b.options.StateMutationGuard = r.StateMutationGuard
	b.options.RefreshVariables = r.RefreshVariables
	state, err = b.TransitionRun(ctx, p, runID, state.Revision, "paused")
	if err != nil {
		t.Fatal(err)
	}
	before := state.Revision
	for _, name := range []string{"entity", "alias", "chain"} {
		if _, err = b.StatePatch(ctx, p, runID, before, map[string]model.Value{name: {Kind: model.StringValue, String: "case-2"}}); err == nil {
			t.Fatalf("confirmed transitive dependency %s patched", name)
		}
	}
	state, err = b.StateGet(ctx, p, runID)
	if err != nil || state.Revision != before || len(state.Variables) != 0 {
		t.Fatalf("rejected alias patch changed durable state: %+v %v", state, err)
	}
	state, err = b.StatePatch(ctx, p, runID, before, map[string]model.Value{"summary": {Kind: model.StringValue, String: "refreshed"}})
	if err != nil || state.Revision != before+1 {
		t.Fatalf("unconsumed binding patch failed: %+v %v", state, err)
	}
	if err = b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	b, err = New(options, dispatch)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	for _, request := range []struct {
		revision        int
		plan, objective string
	}{{state.Revision + 1, state.PlanID, runID}, {state.Revision, "wrong", runID}, {state.Revision, state.PlanID, "wrong"}} {
		if _, err = b.LoadResume(ctx, p, runID, request.revision, request.plan, request.objective); err == nil {
			t.Fatal("resume accepted mismatched identity")
		}
	}
	other, _ := auth.NewPrincipal("fixture:issuer", "", "bob", []string{"desktop:control"})
	if _, err = b.LoadResume(auth.WithPrincipal(ctx, other), other, runID, state.Revision, state.PlanID, runID); err == nil {
		t.Fatal("cross user resume accepted")
	}
	attached := false
	resumed, err := integration.NewWithOptions(b.Execute, integration.Options{LoadResume: b.LoadResume, AttachOperation: func(ctx context.Context, p auth.Principal, run string, revision int, session, operation string) error {
		_, err := b.AttachResumedOperation(ctx, p, run, revision, session, operation)
		attached = err == nil
		return err
	}})
	if err != nil {
		t.Fatal(err)
	}
	stopped = false
	result, err := resumed.Resume(ctx, p, runID, state.Revision, state.PlanID, runID)
	if err != nil {
		t.Fatal(err)
	}
	done, err = resumed.Wait(wait, result.SessionID, result.Operation.ID)
	if err != nil || done.Status != manager.OperationSucceeded {
		t.Fatalf("resume failed: %+v %v", done, err)
	}
	if !attached || mutations != 1 {
		t.Fatalf("correlation or duplicate mutation: attached=%v calls=%d", attached, mutations)
	}
}

func TestGeneratedResumeUnknownEffectBlocksAllNewDispatch(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture:issuer", "", "resume-unknown", []string{"desktop:control"})
	ctx := auth.WithPrincipal(context.Background(), p)
	calls := 0
	b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		calls++
		return integration.StepResult{DispatchState: "unknown", VerificationState: "unknown"}, errors.New("receipt lost")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	r, err := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, LoadResume: b.LoadResume, AttachOperation: func(context.Context, auth.Principal, string, int, string, string) error {
		t.Fatal("uncertain resume attached operation")
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "uncertain fixture")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	for i := range plan.Steps {
		if plan.Steps[i].Effect.Class == model.ExternalNonIdempotent {
			plan.Steps[i].Effect.BusinessKey = map[string]model.Value{"fixtureCase": {Kind: model.StringValue, String: "case-1"}}
		}
	}
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
	if _, err = r.Resume(ctx, p, runID, state.Revision, state.PlanID, runID); !errors.Is(err, ErrNeedsReconciliation) {
		t.Fatalf("expected reconciliation barrier: %v", err)
	}
	if calls != 1 {
		t.Fatalf("unknown effect dispatched twice: %d", calls)
	}
}

func TestKnownAbsentResumeRemainsPendingWithoutReplayingOldIntent(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture:issuer", "", "resume-known-absent", []string{"desktop:control"})
	ctx := auth.WithPrincipal(context.Background(), p)
	var orchestrator *integration.Runtime
	var captured context.Context
	calls := 0
	b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, StateMutationGuard: func(c context.Context, p auth.Principal, run string) (func(), error) {
		return orchestrator.StateMutationGuard(c, p, run)
	}}, func(c context.Context, _ auth.Principal, _ model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		captured = c
		calls++
		return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, errors.New("fixture locator failed before input")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	orchestrator, err = integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, CompleteObjective: b.CompleteObjective})
	if err != nil {
		t.Fatal(err)
	}
	session, err := orchestrator.Open(ctx, "known absence fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer orchestrator.Close(ctx, session.SessionID)
	plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"entity": {Kind: model.StringValue, String: "case-1"}}
	op, err := orchestrator.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err = orchestrator.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	runID, err := orchestrator.RunReference(ctx, session.SessionID, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := b.StateGet(ctx, p, runID)
	if err != nil || state.Status != "paused" || len(state.UnresolvedEffects) != 0 {
		t.Fatalf("known absence has no safe stopped boundary: %+v %v", state, err)
	}
	snapshot, err := b.LoadResume(ctx, p, runID, state.Revision, state.PlanID, state.ObjectiveID)
	if err != nil || len(snapshot.Completed) != 0 || len(snapshot.Plan.Steps) != 1 || snapshot.Plan.Steps[0].ID != plan.Steps[0].ID {
		t.Fatalf("known absent step skipped or rejected: %+v %v", snapshot, err)
	}
	// Admission preserves eligibility without reusing or overwriting a previous
	// durable intent. A later explicit recovery attempt must commit a new intent.
	if _, err = b.Execute(context.WithoutCancel(captured), p, plan.Steps[0], nil); !errors.Is(err, ErrNeedsReconciliation) || calls != 1 {
		t.Fatalf("old absent intent replayed: calls=%d err=%v", calls, err)
	}
}

func TestExplicitAbsentRetryCommitsNewIntentAndSurvivesRestart(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture:issuer", "", "explicit-absent-retry", []string{"desktop:control"})
	ctx := auth.WithPrincipal(context.Background(), p)
	var b *Builder
	var orchestrator *integration.Runtime
	var retryContext context.Context
	targetFound, failAttach := false, true
	calls, effects := 0, 0
	options := Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, StateMutationGuard: func(c context.Context, p auth.Principal, run string) (func(), error) {
		return orchestrator.StateMutationGuard(c, p, run)
	}}
	dispatch := func(c context.Context, p auth.Principal, step model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		calls++
		if !targetFound {
			return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, errors.New("target not found before input")
		}
		metadata, _ := integration.ExecutionFromContext(c)
		if !metadata.Resumed || metadata.OperationID == "" || metadata.StepIndex != 0 {
			return integration.StepResult{}, errors.New("resumed metadata absent or renumbered")
		}
		run, err := load(c, b.users[p.Namespace].server, p, metadata.RunID)
		if err != nil {
			return integration.StepResult{}, err
		}
		if run.EndlySessionId == nil || run.EndlyOperationId == nil || *run.EndlySessionId != metadata.SessionID || *run.EndlyOperationId != metadata.OperationID || len(run.Attempts) != 2 || len(run.Effects) != 2 {
			return integration.StepResult{}, errors.New("retry dispatch preceded committed correlation/intent")
		}
		absent, intent := 0, 0
		for _, effect := range run.Effects {
			if effect.State != nil && *effect.State == "absent" {
				absent++
			}
			if effect.State != nil && *effect.State == "intent" {
				intent++
				if effect.AttemptId == nil || *effect.AttemptId != key("attempt-resume", metadata.RunID, metadata.PlanID, step.ID, metadata.OperationID) {
					return integration.StepResult{}, errors.New("retry lost operation-bound identity")
				}
			}
		}
		if absent != 1 || intent != 1 {
			return integration.StepResult{}, errors.New("retry replaced absent history or lost intent")
		}
		retryContext = c
		effects++
		return integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	}
	var err error
	b, err = New(options, dispatch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close(ctx) }()
	newRuntime := func() (*integration.Runtime, error) {
		return integration.NewWithOptions(func(c context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (integration.StepResult, error) {
			metadata, _ := integration.ExecutionFromContext(c)
			if metadata.Resumed {
				state, readErr := b.StateGet(c, p, metadata.RunID)
				if readErr != nil {
					return integration.StepResult{}, readErr
				}
				t.Logf("fixture scoped StateGet before retry: status=%s revision=%d unresolved=%d", state.Status, state.Revision, len(state.UnresolvedEffects))
				bound, user, readErr := b.bound(c, p, 1)
				if readErr != nil {
					return integration.StepResult{}, readErr
				}
				user.mu.Lock()
				run, readErr := load(bound, user.server, p, metadata.RunID)
				user.mu.Unlock()
				if readErr != nil {
					return integration.StepResult{}, readErr
				}
				for _, effect := range run.Effects {
					t.Logf("fixture scoped LoadRun before retry: effect=%s state=%s", *effect.Id, *effect.State)
				}
			}
			return b.Execute(c, p, step, values)
		}, integration.Options{PreparePlan: b.PreparePlan, CompleteObjective: b.CompleteObjective, LoadResume: b.LoadResume, AttachOperation: func(c context.Context, p auth.Principal, run string, revision int, session, operation string) error {
			if failAttach {
				revision++
			}
			_, err := b.AttachResumedOperation(c, p, run, revision, session, operation)
			return err
		}})
	}
	orchestrator, err = newRuntime()
	if err != nil {
		t.Fatal(err)
	}
	session, err := orchestrator.Open(ctx, "explicit retry fixture")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"entity": {Kind: model.StringValue, String: "case-1"}}
	op, err := orchestrator.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err = orchestrator.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	runID, err := orchestrator.RunReference(ctx, session.SessionID, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := b.StateGet(ctx, p, runID)
	if err != nil || state.Status != "paused" || calls != 1 || effects != 0 {
		t.Fatalf("initial non-dispatch not stopped: %+v %v", state, err)
	}
	originalRevision := state.Revision
	if _, err = orchestrator.ResumeInSession(ctx, p, session.SessionID, runID, state.Revision, state.PlanID, state.ObjectiveID); err == nil {
		t.Fatal("failed correlation CAS admitted retry")
	}
	state, err = b.StateGet(ctx, p, runID)
	if err != nil || state.Revision != originalRevision || calls != 1 || effects != 0 {
		t.Fatal("failed correlation commit dispatched or changed state")
	}
	// StopOperation is asynchronous; observe the inhibited stopped boundary,
	// rather than racing another resume against a cancelling operation.
	boundary := time.NewTimer(3 * time.Second)
	defer boundary.Stop()
	for {
		release, guardErr := orchestrator.StateMutationGuard(ctx, p, runID)
		if guardErr == nil {
			release()
			break
		}
		select {
		case <-boundary.C:
			t.Fatal("rejected resume never stopped")
		case <-time.After(5 * time.Millisecond):
		}
	}
	failAttach, targetFound = false, true
	resumed, err := orchestrator.ResumeInSession(ctx, p, session.SessionID, runID, state.Revision, state.PlanID, state.ObjectiveID)
	if err != nil {
		t.Fatal(err)
	}
	finished, err := orchestrator.Wait(wait, session.SessionID, resumed.Operation.ID)
	if err != nil || finished.Status != manager.OperationSucceeded || effects != 1 || calls != 2 {
		t.Fatalf("explicit retry failed: %+v %v calls=%d effects=%d", finished, err, calls, effects)
	}
	if _, err = b.Execute(context.WithoutCancel(retryContext), p, plan.Steps[0], nil); err != nil || calls != 2 || effects != 1 {
		t.Fatalf("confirmed retry replayed instead of adopted: %v", err)
	}
	state, err = b.StateGet(ctx, p, runID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := b.LoadResume(ctx, p, runID, state.Revision, state.PlanID, state.ObjectiveID)
	if err != nil || len(snapshot.Completed) != 1 {
		t.Fatalf("append-only absent history blocked verified prefix: %+v %v", snapshot, err)
	}
	if err = orchestrator.Close(ctx, session.SessionID); err != nil {
		t.Fatal(err)
	}
	if err = b.Close(ctx); err != nil {
		t.Fatal(err)
	}
	b, err = New(options, dispatch)
	if err != nil {
		t.Fatal(err)
	}
	orchestrator, err = newRuntime()
	if err != nil {
		t.Fatal(err)
	}
	freshSession, err := orchestrator.Open(ctx, "restart verified prefix")
	if err != nil {
		t.Fatal(err)
	}
	defer orchestrator.Close(ctx, freshSession.SessionID)
	state, err = b.StateGet(ctx, p, runID)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := orchestrator.ResumeInSession(ctx, p, freshSession.SessionID, runID, state.Revision, state.PlanID, state.ObjectiveID)
	if err != nil {
		t.Fatal(err)
	}
	finished, err = orchestrator.Wait(wait, freshSession.SessionID, restarted.Operation.ID)
	if err != nil || finished.Status != manager.OperationSucceeded || calls != 2 || effects != 1 {
		t.Fatalf("restart repeated confirmed effect: %+v %v", finished, err)
	}
	if _, err = b.Execute(context.WithoutCancel(retryContext), p, plan.Steps[0], nil); err == nil || effects != 1 {
		t.Fatal("stale resumed operation correlation admitted execution")
	}
}
