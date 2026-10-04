package endly

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/mechanize/script"
	"testing"
	"time"
)

func TestObjectiveCompletionReceivesIdentityMetadataAndLiveBinding(t *testing.T) {
	ctx := actor(t, "objective-alice")
	actorPrincipal, _ := auth.FromContext(ctx)
	seen := make(chan CompletionRequest, 1)
	r, err := NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		v := model.Value{Kind: model.StringValue, String: "case-1"}
		return StepResult{Value: &v, DispatchState: "notDispatched", VerificationState: "verified"}, nil
	}, Options{CompleteObjective: func(c context.Context, p auth.Principal, request CompletionRequest) (BusinessResult, error) {
		actual, e := auth.FromContext(c)
		if e != nil || actual.Namespace != actorPrincipal.Namespace || p.Namespace != actorPrincipal.Namespace {
			t.Error("principal lost")
		}
		seen <- request
		return BusinessResult{BusinessStatus: "unverified", VerificationState: "unknown", Objective: &objective.Result{Truth: objective.Unknown}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "business fixture")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := script.Compile(`let caseReceipt = app("com.example.Fixture").getById("status").read("value")`)
	if err != nil {
		t.Fatal(err)
	}
	op, err := r.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = r.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	request := <-seen
	if request.Metadata.RunID == "" || request.Metadata.PlanID == "" || request.Metadata.SessionID != session.SessionID || request.Values["binding.caseReceipt"].String != "case-1" {
		t.Fatalf("completion context missing: %+v", request)
	}
	result, err := r.Result(ctx, session.SessionID, op.ID)
	if err != nil || result.BusinessStatus != "unverified" {
		t.Fatalf("unknown promoted: %+v %v", result, err)
	}
	if _, err = r.Result(actor(t, "objective-bob"), session.SessionID, op.ID); err == nil {
		t.Fatal("cross principal outcome read")
	}
}

func TestNoObjectiveCallbackCannotPromoteDispatchSuccess(t *testing.T) {
	ctx := actor(t, "objective-default")
	r, _ := New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		return StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	})
	session, _ := r.Open(ctx, "unverified fixture")
	plan, _ := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	op, err := r.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = r.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	result, err := r.Result(ctx, session.SessionID, op.ID)
	if err != nil || result.BusinessStatus != "unverified" || result.VerificationState != "unverified" {
		t.Fatalf("dispatch promoted to business completion: %+v %v", result, err)
	}
}
