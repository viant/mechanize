package endly

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func actor(t *testing.T, subject string) context.Context {
	t.Helper()
	p, err := auth.NewPrincipal("fixture:issuer", "", subject, []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	return auth.WithPrincipal(context.Background(), p)
}
func TestEndlyRunsSharedPlanAndRetainsTypedValues(t *testing.T) {
	var mu sync.Mutex
	var actions []string
	runtime, err := New(func(ctx context.Context, p auth.Principal, s model.Step, values map[string]model.Value) (StepResult, error) {
		if actual, err := auth.FromContext(ctx); err != nil || actual.Namespace != p.Namespace {
			return StepResult{}, errors.New("identity lost")
		}
		mu.Lock()
		actions = append(actions, s.Action)
		mu.Unlock()
		if s.Action == "element.read" {
			value := model.Value{Kind: model.StringValue, String: "literal ${danger} $text"}
			return StepResult{Value: &value, DispatchState: "notDispatched", VerificationState: "verified"}, nil
		}
		value, err := model.ResolveValue(s.Arguments["value"], values)
		if err != nil {
			return StepResult{}, err
		}
		if value.String != "literal ${danger} $text" {
			return StepResult{}, errors.New("typed value was expanded")
		}
		return StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := actor(t, "alice")
	session, err := runtime.Open(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx, session.SessionID)
	plan, err := script.Compile("let content = app(\"com.example.Fixture\").getById(\"source\").read(\"value\")\nweb.tab(origin: \"https://fixture.example\").getByLabel(\"Summary\").fill(content)")
	if err != nil {
		t.Fatal(err)
	}
	operation, err := runtime.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	finished, err := runtime.Wait(deadline, session.SessionID, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if finished.Status != manager.OperationSucceeded {
		t.Fatalf("operation failed: %+v", finished)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(actions) != 2 || actions[0] != "element.read" || actions[1] != "element.fill" {
		t.Fatalf("wrong task order: %v", actions)
	}
	if _, err := runtime.Status(actor(t, "bob"), session.SessionID, operation.ID); err == nil {
		t.Fatal("cross-user operation read admitted")
	}
}
func TestEndlyCancellationAndFailure(t *testing.T) {
	started := make(chan struct{})
	runtime, _ := New(func(ctx context.Context, _ auth.Principal, _ model.Step, _ map[string]model.Value) (StepResult, error) {
		close(started)
		<-ctx.Done()
		return StepResult{}, ctx.Err()
	})
	ctx := actor(t, "alice")
	session, err := runtime.Open(ctx, "cancel")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx, session.SessionID)
	plan, err := script.Compile("app(\"com.example.Fixture\").getById(\"save\").click()")
	if err != nil {
		t.Fatal(err)
	}
	operation, err := runtime.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("Endly did not execute action")
	}
	if _, err = runtime.Cancel(ctx, session.SessionID, operation.ID); err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, err := runtime.Wait(wait, session.SessionID, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != manager.OperationCancelled {
		t.Fatalf("cancel did not propagate: %+v", result)
	}
}
