package endly

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestDeclaredDefaultsMatchPreparationDispatchAndDeduplication(t *testing.T) {
	ctx := actor(t, "default-inputs")
	plan, err := script.Compile(`app("com.example.Fixture").getById("status").read("name")`)
	if err != nil {
		t.Fatal(err)
	}
	value := model.Value{Kind: model.StringValue, String: "default-label"}
	plan.Inputs = map[string]model.InputDefinition{"label": {Type: model.StringValue, Required: true, Default: &value}}
	var dispatches, prepares atomic.Int32
	received := make(chan model.Value, 1)
	r, err := NewWithOptions(func(_ context.Context, _ auth.Principal, _ model.Step, values map[string]model.Value) (StepResult, error) {
		dispatches.Add(1)
		received <- values["input.label"]
		return StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
	}, Options{PreparePlan: func(_ context.Context, _ auth.Principal, _, _ string, _ model.Plan, inputs map[string]model.Value) (string, error) {
		prepares.Add(1)
		if inputs["label"].String != "default-label" {
			t.Error("preparation lost default")
		}
		return "prepared-plan", nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "defaults")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.SessionID)
	op, err := r.StartPlanWithRequest(ctx, session.SessionID, "same-request", *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = r.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case actual := <-received:
		if !reflect.DeepEqual(actual, value) {
			t.Fatal("dispatch default differs", actual)
		}
	case <-wait.Done():
		t.Fatal("default input never reached executor")
	}
	repeated, err := r.StartPlanWithRequest(ctx, session.SessionID, "same-request", *plan, map[string]model.Value{"label": value})
	if err != nil || repeated.ID != op.ID || prepares.Load() != 1 || dispatches.Load() != 1 {
		t.Fatal("equivalent default request replayed or conflicted", err)
	}
	changed := model.Value{Kind: model.StringValue, String: "different-label"}
	if _, err := r.StartPlanWithRequest(ctx, session.SessionID, "same-request", *plan, map[string]model.Value{"label": changed}); err == nil {
		t.Fatal("changed input reused an admitted request identity")
	}
	if prepares.Load() != 1 || dispatches.Load() != 1 {
		t.Fatal("conflicting input reached preparation or dispatch")
	}
}

func TestRuntimeDetachesNestedInputValuesBeforeAsyncDispatch(t *testing.T) {
	ctx := actor(t, "nested-inputs")
	plan, err := script.Compile(`app("com.example.Fixture").getById("status").read("name")`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Inputs = map[string]model.InputDefinition{"options": {Type: model.ObjectValue, Required: true}}
	gate := make(chan struct{})
	received := make(chan string, 1)
	r, err := New(func(_ context.Context, _ auth.Principal, _ model.Step, values map[string]model.Value) (StepResult, error) {
		<-gate
		received <- values["input.options"].Object["label"].String
		return StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "nested inputs")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.SessionID)
	object := map[string]model.Value{"label": {Kind: model.StringValue, String: "original"}}
	op, err := r.StartPlan(ctx, session.SessionID, *plan, map[string]model.Value{"options": {Kind: model.ObjectValue, Object: object}})
	if err != nil {
		close(gate)
		t.Fatal(err)
	}
	object["label"] = model.Value{Kind: model.StringValue, String: "changed-after-admission"}
	close(gate)
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = r.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got != "original" {
			t.Fatal("caller mutation changed admitted inputs")
		}
	case <-wait.Done():
		t.Fatal("nested input never reached executor")
	}
}

func TestDeclaredInputReferenceRetainsTypeUntilResolution(t *testing.T) {
	ctx := actor(t, "reference-inputs")
	plan, err := script.Compile(`app("com.example.Fixture").getById("status").read("name")`)
	if err != nil {
		t.Fatal(err)
	}
	fallback := model.Value{Kind: model.StringValue, String: "default-label"}
	plan.Inputs = map[string]model.InputDefinition{
		"source": {Type: model.StringValue, Default: &fallback},
		"label":  {Type: model.StringValue, Required: true},
	}
	var dispatches atomic.Int32
	r, err := New(func(_ context.Context, _ auth.Principal, _ model.Step, values map[string]model.Value) (StepResult, error) {
		dispatches.Add(1)
		alias := values["input.label"]
		if alias.Kind != model.ReferenceValue || alias.Expected != model.StringValue {
			t.Error("input alias lost declared type")
		}
		actual, resolveErr := model.ResolveValue(alias, values)
		if resolveErr != nil || actual.String != fallback.String {
			t.Error("defaulted alias did not resolve", resolveErr)
		}
		values["input.source"] = model.Value{Kind: model.NumberValue, Number: 42}
		if _, resolveErr = model.ResolveValue(alias, values); resolveErr == nil {
			t.Error("alias accepted wrong terminal type")
		}
		return StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "reference defaults")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.SessionID)
	alias := model.Value{Kind: model.ReferenceValue, Ref: "input.source"}
	op, err := r.StartPlanWithRequest(ctx, session.SessionID, "reference-request", *plan, map[string]model.Value{"label": alias})
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = r.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	alias.Expected = model.StringValue
	repeated, err := r.StartPlanWithRequest(ctx, session.SessionID, "reference-request", *plan, map[string]model.Value{"label": alias})
	if err != nil || repeated.ID != op.ID || dispatches.Load() != 1 {
		t.Fatal("explicit and implicit reference types conflict", err)
	}
}

func TestInputValidationPrecedesLossyClone(t *testing.T) {
	ctx := actor(t, "invalid-input-union")
	plan, err := script.Compile(`app("com.example.Fixture").getById("status").read("name")`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Inputs = map[string]model.InputDefinition{"label": {Type: model.StringValue, Required: true}}
	var prepares atomic.Int32
	r, err := NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		t.Error("invalid input dispatched")
		return StepResult{}, nil
	}, Options{PreparePlan: func(context.Context, auth.Principal, string, string, model.Plan, map[string]model.Value) (string, error) {
		prepares.Add(1)
		return "invalid-preparation", nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "invalid input")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.SessionID)
	for _, value := range []model.Value{
		{Kind: model.StringValue, String: "label", Object: map[string]model.Value{}},
		{Kind: model.StringValue, String: "label", Array: []model.Value{}},
	} {
		if _, err := r.StartPlan(ctx, session.SessionID, *plan, map[string]model.Value{"label": value}); err == nil {
			t.Error("invalid union accepted after clone")
		}
	}
	if prepares.Load() != 0 {
		t.Fatal("invalid union persisted")
	}
}
