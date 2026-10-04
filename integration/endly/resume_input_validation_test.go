package endly

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestResumeRejectsInvalidPersistedValuesBeforeAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ResumeSnapshot)
	}{
		{"missing required", func(s *ResumeSnapshot) { delete(s.Inputs, "label") }},
		{"missing required with default", func(s *ResumeSnapshot) {
			delete(s.Inputs, "label")
			d := s.Plan.Inputs["label"]
			v := model.Value{Kind: model.StringValue, String: "default"}
			d.Default = &v
			s.Plan.Inputs["label"] = d
		}},
		{"wrong literal type", func(s *ResumeSnapshot) { s.Inputs["label"] = model.Value{Kind: model.NumberValue, Number: 3} }},
		{"wrong reference expected type", func(s *ResumeSnapshot) {
			s.Inputs["label"] = model.Value{Kind: model.ReferenceValue, Ref: "binding.later", Expected: model.NumberValue}
		}},
		{"invalid reference namespace", func(s *ResumeSnapshot) {
			s.Inputs["label"] = model.Value{Kind: model.ReferenceValue, Ref: "invalid.later", Expected: model.StringValue}
		}},
		{"input empty object union", func(s *ResumeSnapshot) {
			s.Inputs["label"] = model.Value{Kind: model.StringValue, Object: map[string]model.Value{}}
		}},
		{"extra input empty array union", func(s *ResumeSnapshot) {
			s.Inputs["extra"] = model.Value{Kind: model.StringValue, Array: []model.Value{}}
		}},
		{"input nested union", func(s *ResumeSnapshot) {
			s.Inputs["extra"] = model.Value{Kind: model.ObjectValue, Object: map[string]model.Value{"nested": {Kind: model.StringValue, Array: []model.Value{}}}}
		}},
		{"value empty object union", func(s *ResumeSnapshot) {
			s.Values["result"] = model.Value{Kind: model.StringValue, Object: map[string]model.Value{}}
		}},
		{"value empty array union", func(s *ResumeSnapshot) {
			s.Values["result"] = model.Value{Kind: model.StringValue, Array: []model.Value{}}
		}},
		{"completed empty object union", func(s *ResumeSnapshot) {
			v := model.Value{Kind: model.StringValue, Object: map[string]model.Value{}}
			s.Completed[s.Plan.Steps[0].ID] = StepResult{VerificationState: "verified", Value: &v}
		}},
		{"completed empty array union", func(s *ResumeSnapshot) {
			v := model.Value{Kind: model.StringValue, Array: []model.Value{}}
			s.Completed[s.Plan.Steps[0].ID] = StepResult{VerificationState: "verified", Value: &v}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := actor(t, "invalid-resume-inputs")
			principal, _ := auth.FromContext(ctx)
			plan, err := script.Compile(`app("com.example.Fixture").getById("status").read("name")`)
			if err != nil {
				t.Fatal(err)
			}
			plan.Inputs = map[string]model.InputDefinition{"label": {Type: model.StringValue, Required: true}}
			snapshot := ResumeSnapshot{RunID: "run", PlanID: "plan", ObjectiveID: "objective", Revision: 3, Status: "paused", Plan: *plan, Inputs: map[string]model.Value{"label": {Kind: model.StringValue, String: "valid"}}, Values: map[string]model.Value{}, Completed: map[string]StepResult{}}
			test.mutate(&snapshot)
			var loads, attaches, dispatches atomic.Int32
			r, err := NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
				dispatches.Add(1)
				return StepResult{VerificationState: "verified"}, nil
			}, Options{
				LoadResume: func(context.Context, auth.Principal, string, int, string, string) (ResumeSnapshot, error) {
					loads.Add(1)
					return snapshot, nil
				},
				AttachOperation: func(context.Context, auth.Principal, string, int, string, string) error { attaches.Add(1); return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			session, err := r.Open(ctx, "invalid resume")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(ctx, session.SessionID)
			result, err := r.ResumeInSession(ctx, principal, session.SessionID, "run", 3, "plan", "objective")
			if err == nil || result != nil {
				t.Fatalf("invalid snapshot admitted: result=%+v err=%v", result, err)
			}
			if loads.Load() != 1 || attaches.Load() != 0 || dispatches.Load() != 0 {
				t.Fatalf("invalid admission: loads=%d attach=%d dispatch=%d", loads.Load(), attaches.Load(), dispatches.Load())
			}
			r.mu.RLock()
			programs := len(r.programs)
			r.mu.RUnlock()
			if programs != 0 {
				t.Fatal("invalid snapshot registered a program")
			}
		})
	}
}

func TestResumePreservesLateReferencesAndAbsentOptionalInputs(t *testing.T) {
	ctx := actor(t, "late-resume-inputs")
	principal, _ := auth.FromContext(ctx)
	plan, err := script.Compile("app(\"com.example.Fixture\").getById(\"first\").read(\"name\")\napp(\"com.example.Fixture\").getById(\"second\").read(\"name\")")
	if err != nil {
		t.Fatal(err)
	}
	defaultValue := model.Value{Kind: model.StringValue, String: "unused-default"}
	plan.Inputs = map[string]model.InputDefinition{
		"label":           {Type: model.StringValue, Required: true},
		"optional":        {Type: model.StringValue},
		"optionalDefault": {Type: model.StringValue, Default: &defaultValue},
	}
	rawRef := model.Value{Kind: model.ReferenceValue, Ref: "binding.later"}
	snapshot := ResumeSnapshot{RunID: "run", PlanID: "plan", ObjectiveID: "objective", Revision: 3, Status: "paused", Plan: *plan, Inputs: map[string]model.Value{"label": rawRef}, Values: map[string]model.Value{"result": {Kind: model.StringValue, String: "persisted"}}, Completed: map[string]StepResult{plan.Steps[0].ID: {VerificationState: "verified", Value: &defaultValue}}}
	var calls, attaches atomic.Int32
	r, err := NewWithOptions(func(ctx context.Context, _ auth.Principal, step model.Step, values map[string]model.Value) (StepResult, error) {
		calls.Add(1)
		if step.ID != plan.Steps[1].ID || attaches.Load() != 1 {
			t.Error("completed step replayed or correlation missing")
		}
		alias := values["input.label"]
		if alias.Ref != rawRef.Ref || alias.Expected != model.StringValue {
			t.Error("late reference lost declared constraint")
		}
		if _, ok := values["input.optional"]; ok {
			t.Error("absent optional input added")
		}
		if _, ok := values["input.optionalDefault"]; ok {
			t.Error("absent persisted default silently added")
		}
		if values["binding.result"].String != "persisted" {
			t.Error("durable value lost")
		}
		values["binding.later"] = model.Value{Kind: model.StringValue, String: "resolved-later"}
		actual, resolveErr := model.ResolveValue(alias, values)
		if resolveErr != nil || actual.String != "resolved-later" {
			t.Error("late reference failed", resolveErr)
		}
		values["binding.later"] = model.Value{Kind: model.NumberValue, Number: 3}
		if _, resolveErr = model.ResolveValue(alias, values); resolveErr == nil {
			t.Error("late reference accepted incompatible terminal type")
		}
		return StepResult{VerificationState: "verified"}, nil
	}, Options{LoadResume: func(context.Context, auth.Principal, string, int, string, string) (ResumeSnapshot, error) {
		return snapshot, nil
	}, AttachOperation: func(context.Context, auth.Principal, string, int, string, string) error { attaches.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "late resume")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.SessionID)
	result, err := r.ResumeInSession(ctx, principal, session.SessionID, "run", 3, "plan", "objective")
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	finished, err := r.Wait(wait, session.SessionID, result.Operation.ID)
	if err != nil || finished.Status != manager.OperationSucceeded || calls.Load() != 1 {
		t.Fatalf("resume failed: %+v %v calls=%d", finished, err, calls.Load())
	}
	if !reflect.DeepEqual(snapshot.Inputs, map[string]model.Value{"label": rawRef}) {
		t.Fatal("loader-owned immutable inputs changed")
	}
}

func TestStartPlanPersistedDefaultsAndReferencesSurviveResume(t *testing.T) {
	ctx := actor(t, "start-resume-inputs")
	principal, _ := auth.FromContext(ctx)
	plan, err := script.Compile("app(\"com.example.Fixture\").getById(\"first\").read(\"name\")\napp(\"com.example.Fixture\").getById(\"second\").read(\"name\")")
	if err != nil {
		t.Fatal(err)
	}
	fallback := model.Value{Kind: model.StringValue, String: "persisted-default"}
	plan.Inputs = map[string]model.InputDefinition{"source": {Type: model.StringValue, Required: true, Default: &fallback}, "label": {Type: model.StringValue, Required: true}}
	var snapshot ResumeSnapshot
	var firstVerified, secondNotDispatched atomic.Int32
	initial, err := NewWithOptions(func(_ context.Context, _ auth.Principal, step model.Step, _ map[string]model.Value) (StepResult, error) {
		if step.ID == plan.Steps[0].ID {
			firstVerified.Add(1)
			result := StepResult{DispatchState: "notDispatched", VerificationState: "verified"}
			snapshot.Completed[step.ID] = result
			return result, nil
		}
		secondNotDispatched.Add(1)
		return StepResult{DispatchState: "notDispatched"}, errors.New("fixture stopped before second dispatch")
	}, Options{PreparePlan: func(_ context.Context, _ auth.Principal, runID, _ string, p model.Plan, inputs map[string]model.Value) (string, error) {
		snapshot = ResumeSnapshot{RunID: runID, PlanID: "prepared-plan", ObjectiveID: "objective", Revision: 3, Status: "paused", Plan: p, Inputs: inputs, Completed: map[string]StepResult{}}
		return snapshot.PlanID, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	initialSession, err := initial.Open(ctx, "start")
	if err != nil {
		t.Fatal(err)
	}
	operation, err := initial.StartPlan(ctx, initialSession.SessionID, *plan, map[string]model.Value{"label": {Kind: model.ReferenceValue, Ref: "input.source"}})
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stopped, err := initial.Wait(wait, initialSession.SessionID, operation.ID)
	if err != nil || stopped.Status != manager.OperationFailed || firstVerified.Load() != 1 || secondNotDispatched.Load() != 1 {
		t.Fatalf("initial boundary: %+v %v first=%d secondNotDispatched=%d", stopped, err, firstVerified.Load(), secondNotDispatched.Load())
	}
	if err = initial.Close(ctx, initialSession.SessionID); err != nil {
		t.Fatal(err)
	}
	if snapshot.Inputs["source"].String != fallback.String || snapshot.Inputs["label"].Expected != model.StringValue {
		t.Fatal("initial admission did not persist effective input contract")
	}
	var calls, attaches atomic.Int32
	resumed, err := NewWithOptions(func(_ context.Context, _ auth.Principal, step model.Step, values map[string]model.Value) (StepResult, error) {
		calls.Add(1)
		if step.ID != plan.Steps[1].ID || attaches.Load() != 1 {
			t.Error("resume replayed completed step or dispatched before attach")
		}
		actual, resolveErr := model.ResolveValue(values["input.label"], values)
		if resolveErr != nil || !reflect.DeepEqual(actual, fallback) {
			t.Error("persisted default reference changed", resolveErr)
		}
		return StepResult{VerificationState: "verified"}, nil
	}, Options{LoadResume: func(context.Context, auth.Principal, string, int, string, string) (ResumeSnapshot, error) {
		return snapshot, nil
	}, AttachOperation: func(context.Context, auth.Principal, string, int, string, string) error { attaches.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	session, err := resumed.Open(ctx, "resume after restart")
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close(ctx, session.SessionID)
	result, err := resumed.ResumeInSession(ctx, principal, session.SessionID, snapshot.RunID, 3, "prepared-plan", "objective")
	if err != nil {
		t.Fatal(err)
	}
	finished, err := resumed.Wait(wait, session.SessionID, result.Operation.ID)
	if err != nil || finished.Status != manager.OperationSucceeded || calls.Load() != 1 {
		t.Fatalf("restart resume: %+v %v calls=%d", finished, err, calls.Load())
	}
	// Keep both initial persisted values exact, including normalized Expected.
	if !reflect.DeepEqual(snapshot.Inputs, map[string]model.Value{
		"source": fallback,
		"label":  {Kind: model.ReferenceValue, Ref: "input.source", Expected: model.StringValue},
	}) {
		t.Fatal("resume altered persisted inputs")
	}
}
