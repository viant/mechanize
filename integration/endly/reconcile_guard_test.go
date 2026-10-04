package endly

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func reconciliationGuardPlan(t *testing.T) model.Plan {
	t.Helper()
	plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	return *plan
}

func newReconciliationGuardRuntime(t *testing.T, execute Execute, options Options) (*Runtime, context.Context, auth.Principal, string) {
	t.Helper()
	r, err := NewWithOptions(execute, options)
	if err != nil {
		t.Fatal(err)
	}
	ctx := actor(t, "reconcile-guard")
	p, err := auth.FromContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "reconciliation guard fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := r.Shutdown(cleanupCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("runtime cleanup: %v", err)
		}
	})
	return r, ctx, p, session.SessionID
}

func waitSignal(t *testing.T, signal <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func waitAdmissionHeld(t *testing.T, r *Runtime) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !r.admission.TryLock() {
			return
		}
		r.admission.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("reconciliation guard did not acquire admission")
}

func TestReconciliationGuardRejectsAnyOverlappingRunningOperation(t *testing.T) {
	started := make(chan struct{})
	allowFinish := make(chan struct{})
	r, ctx, p, session := newReconciliationGuardRuntime(t, func(ctx context.Context, _ auth.Principal, _ model.Step, _ map[string]model.Value) (StepResult, error) {
		select {
		case <-started:
		default:
			close(started)
		}
		select {
		case <-allowFinish:
			return StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
		case <-ctx.Done():
			return StepResult{}, ctx.Err()
		}
	}, Options{})
	plan := reconciliationGuardPlan(t)
	operation, err := r.StartPlan(ctx, session, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	waitSignal(t, started, "running Endly action")
	runID, err := r.RunReference(ctx, session, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{runID, "different-run"} {
		release, err := r.ReconciliationGuard(ctx, p, target)
		if err == nil {
			if release != nil {
				release()
			}
			t.Fatalf("guard admitted overlapping operation for target %q", target)
		}
		if release != nil {
			t.Fatalf("rejected guard returned a release callback for target %q", target)
		}
	}
	close(allowFinish)
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := r.Wait(waitCtx, session, operation.ID); err != nil {
		t.Fatalf("wait for fixture operation: %v", err)
	}
}

func TestReconciliationGuardWaitsForObjectiveCallbackWithoutDeadlock(t *testing.T) {
	callbackEntered := make(chan struct{}, 1)
	allowCallback := make(chan struct{})
	var callbackRelease sync.Once
	releaseCallback := func() {
		callbackRelease.Do(func() { close(allowCallback) })
	}
	defer releaseCallback()
	r, ctx, p, session := newReconciliationGuardRuntime(t, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		return StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	}, Options{CompleteObjective: func(context.Context, auth.Principal, CompletionRequest) (BusinessResult, error) {
		callbackEntered <- struct{}{}
		<-allowCallback
		return BusinessResult{BusinessStatus: "unverified", VerificationState: "unknown"}, nil
	}})
	operation, err := r.StartPlan(ctx, session, reconciliationGuardPlan(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	waitSignal(t, callbackEntered, "objective callback")
	runID, err := r.RunReference(ctx, session, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	guardResult := make(chan struct {
		release func()
		err     error
	}, 1)
	go func() {
		release, err := r.ReconciliationGuard(ctx, p, runID)
		guardResult <- struct {
			release func()
			err     error
		}{release, err}
	}()
	waitAdmissionHeld(t, r)
	select {
	case result := <-guardResult:
		if result.release != nil {
			result.release()
		}
		t.Fatalf("guard returned before objective callback completed: %v", result.err)
	case <-time.After(30 * time.Millisecond):
	}
	releaseCallback()
	select {
	case result := <-guardResult:
		if result.err != nil || result.release == nil {
			t.Fatalf("guard failed after objective callback completion: release=%v err=%v", result.release != nil, result.err)
		}
		result.release()
	case <-time.After(5 * time.Second):
		t.Fatal("guard deadlocked after objective callback completed")
	}
}

func TestReconciliationGuardCancellationReleasesAdmission(t *testing.T) {
	callbackEntered := make(chan struct{}, 1)
	allowCallback := make(chan struct{})
	defer close(allowCallback)
	r, ctx, p, session := newReconciliationGuardRuntime(t, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		return StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	}, Options{CompleteObjective: func(context.Context, auth.Principal, CompletionRequest) (BusinessResult, error) {
		callbackEntered <- struct{}{}
		<-allowCallback
		return BusinessResult{BusinessStatus: "unverified", VerificationState: "unknown"}, nil
	}})
	operation, err := r.StartPlan(ctx, session, reconciliationGuardPlan(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	waitSignal(t, callbackEntered, "blocked objective callback")
	runID, err := r.RunReference(ctx, session, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	guardCtx, cancel := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() {
		release, err := r.ReconciliationGuard(guardCtx, p, runID)
		if release != nil {
			release()
		}
		result <- err
	}()
	waitAdmissionHeld(t, r)
	select {
	case err := <-result:
		t.Fatalf("guard returned before cancellation while callback was blocked: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("guard cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guard did not release admission after cancellation")
	}
	// A subsequent admission proves the canceled guard released Runtime.admission.
	release, err := r.StateMutationGuard(ctx, p, "unrelated-run")
	if err != nil {
		t.Fatalf("admission remained locked after cancellation: %v", err)
	}
	release()
}

func TestReconciliationGuardHoldsAdmissionUntilRelease(t *testing.T) {
	r, ctx, p, session := newReconciliationGuardRuntime(t, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		return StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	}, Options{})
	releaseGuard, err := r.ReconciliationGuard(ctx, p, "new-run")
	if err != nil || releaseGuard == nil {
		t.Fatalf("could not acquire guard: release=%v err=%v", releaseGuard != nil, err)
	}
	var guardRelease sync.Once
	release := func() { guardRelease.Do(releaseGuard) }
	defer release()
	started := make(chan struct{})
	result := make(chan error, 1)
	plan := reconciliationGuardPlan(t)
	go func() {
		close(started)
		_, err := r.StartPlan(ctx, session, plan, nil)
		result <- err
	}()
	waitSignal(t, started, "competing admission request")
	select {
	case err := <-result:
		t.Fatalf("new operation passed the held reconciliation guard: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	release()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("operation admission failed after guard release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("operation admission remained blocked after guard release")
	}
}
