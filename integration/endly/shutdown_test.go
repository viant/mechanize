package endly

import (
	"context"
	"errors"
	"testing"
	"time"

	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func shutdownPlan(t *testing.T) model.Plan {
	t.Helper()
	plan, err := script.Compile(`app("com.fixture.app").getById("fixture", exact: true).read("text")`)
	if err != nil {
		t.Fatal(err)
	}
	return *plan
}
func TestShutdownCancelsAndJoinsAllOwnedEndlySessions(t *testing.T) {
	started := make(chan struct{}, 2)
	stopped := make(chan struct{}, 2)
	runtime, err := New(func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (StepResult, error) {
		started <- struct{}{}
		<-ctx.Done()
		stopped <- struct{}{}
		return StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	var sessions []*manager.SessionInfo
	for _, subject := range []string{"first-owner", "second-owner"} {
		ctx := actor(t, subject)
		session, err := runtime.Open(ctx, subject)
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
		if _, err = runtime.StartPlan(ctx, session.SessionID, shutdownPlan(t), nil); err != nil {
			t.Fatal(err)
		}
	}
	for range sessions {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("actualEndly fixture didnotstart")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := runtime.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	for range sessions {
		select {
		case <-stopped:
		default:
			t.Fatal("shutdown didnotjoinexecute")
		}
	}
	runtime.mu.RLock()
	owners, programs := len(runtime.principals), len(runtime.programs)
	runtime.mu.RUnlock()
	if owners != 0 || programs != 0 {
		t.Fatalf("ownedcache retainedafterconfirmedstop %d %d", owners, programs)
	}
	owner := actor(t, "first-owner")
	if _, err = runtime.Open(owner, "late"); !errors.Is(err, ErrShutdownPending) {
		t.Fatalf("newsession admitted %v", err)
	}
	if _, err = runtime.StartPlan(owner, sessions[0].SessionID, shutdownPlan(t), nil); !errors.Is(err, ErrShutdownPending) {
		t.Fatalf("newplan admitted %v", err)
	}
	p, _ := auth.FromContext(owner)
	if _, err = runtime.ResumeInSession(owner, p, sessions[0].SessionID, "run", 1, "plan", "objective"); !errors.Is(err, ErrShutdownPending) {
		t.Fatalf("resume admitted %v", err)
	}
}
func TestShutdownTimeoutRetainsUnconfirmedSessionUntilActionJoins(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	runtime, err := New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		close(started)
		<-release
		return StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, errors.New("noncooperative fixture finally stopped")
	})
	if err != nil {
		t.Fatal(err)
	}
	owner := actor(t, "noncooperative")
	session, err := runtime.Open(owner, "pending")
	if err != nil {
		t.Fatal(err)
	}
	op, err := runtime.StartPlan(owner, session.SessionID, shutdownPlan(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err = runtime.Shutdown(ctx); !errors.Is(err, ErrShutdownPending) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unknownshutdown claimedcomplete %v", err)
	}
	runtime.mu.RLock()
	owners, programs := len(runtime.principals), len(runtime.programs)
	runtime.mu.RUnlock()
	if owners != 1 || programs != 1 {
		t.Fatal("unconfirmedownedstate discarded")
	}
	if current, err := runtime.Status(owner, session.SessionID, op.ID); err != nil || current.Status != manager.OperationCancelling {
		t.Fatalf("pendingstate cannotinspect %+v %v", current, err)
	}
	close(release)
	joined, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	if err = runtime.Shutdown(joined); err != nil {
		t.Fatalf("eventualjoin failed %v", err)
	}
}
func TestShutdownCancelsAndJoinsObjectiveCallbackContext(t *testing.T) {
	objectiveStarted := make(chan struct{})
	objectiveStopped := make(chan struct{})
	runtime, err := NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		return StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
	}, Options{CompleteObjective: func(ctx context.Context, p auth.Principal, request CompletionRequest) (BusinessResult, error) {
		close(objectiveStarted)
		<-ctx.Done()
		close(objectiveStopped)
		return BusinessResult{BusinessStatus: "unverified", VerificationState: "unknown"}, ctx.Err()
	}})
	if err != nil {
		t.Fatal(err)
	}
	owner := actor(t, "objective-owner")
	session, err := runtime.Open(owner, "objective")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.StartPlan(owner, session.SessionID, shutdownPlan(t), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-objectiveStarted:
	case <-time.After(time.Second):
		t.Fatal("objective callback notstarted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = runtime.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-objectiveStopped:
	default:
		t.Fatal("objectivecallback notjoined")
	}
}

func TestShutdownDoesNotDeclareObjectiveQuiescenceWhenCallbackIgnoresCancel(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	runtime, err := NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		return StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
	}, Options{CompleteObjective: func(context.Context, auth.Principal, CompletionRequest) (BusinessResult, error) {
		close(started)
		<-release
		return BusinessResult{BusinessStatus: "unverified", VerificationState: "unknown"}, errors.New("objectivefixturestopped")
	}})
	if err != nil {
		t.Fatal(err)
	}
	owner := actor(t, "stalled-objective")
	session, err := runtime.Open(owner, "stalledobjective")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.StartPlan(owner, session.SessionID, shutdownPlan(t), nil); err != nil {
		t.Fatal(err)
	}
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err = runtime.Shutdown(ctx); !errors.Is(err, ErrShutdownPending) {
		t.Fatalf("noncooperativeobjective claimedquiescent %v", err)
	}
	runtime.mu.RLock()
	pending := len(runtime.completionWorkers)
	owners := len(runtime.principals)
	runtime.mu.RUnlock()
	if pending != 1 || owners != 1 {
		t.Fatal("pendingobjective orsession state discarded")
	}
	close(release)
	joined, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	if err = runtime.Shutdown(joined); err != nil {
		t.Fatal(err)
	}
}
