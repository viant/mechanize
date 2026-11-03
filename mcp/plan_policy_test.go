package mcp

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestRunPlanPolicyStillValidatesAndNeverFallsBackAfterRefusal(t *testing.T) {
	var global, scoped, actions atomic.Int32
	mode := "allow"
	d, id, ctx, session := completionFixture(t, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		actions.Add(1)
		return automation.StepResult{Value: &model.Value{Kind: model.StringValue, String: "fixture"}}, nil
	}, automation.Options{}, func(deps *Dependencies) {
		deps.Policy = func(context.Context, auth.Principal) (script.Policy, error) {
			global.Add(1)
			return script.Policy{}, errors.New("unexpected global discovery")
		}
		deps.PlanPolicy = func(_ context.Context, _ auth.Principal, plan *model.Plan) (script.Policy, error) {
			scoped.Add(1)
			if len(plan.Steps) != 1 || plan.Steps[0].Target.Surface.Kind != "native" {
				t.Fatal("compiled plan not supplied")
			}
			if mode == "error" {
				return script.Policy{}, errors.New("scoped discovery unavailable")
			}
			policy := script.Policy{AllowedSurfaces: map[string]bool{"com.example.Fixture": mode == "allow"}, Capabilities: map[string]bool{"native:attributeRead": true, "native:idLocator": true}}
			return policy, nil
		}
	})
	for _, m := range []string{"allow", "deny", "error"} {
		mode = m
		r := controllerCall(t, d, ctx, id, "mechanize_step_run", completionArgs(session, m, 5000))
		if m == "allow" {
			op := completionOperation(t, r.StructuredContent)
			if op.ExecutionStatus != "succeeded" {
				t.Fatal(op)
			}
		} else if r.IsError == nil || !*r.IsError {
			t.Fatal("refusal accepted", m)
		}
	}
	if global.Load() != 0 || scoped.Load() != 3 || actions.Load() != 1 {
		t.Fatalf("unexpected discovery/dispatch global=%d scoped=%d actions=%d", global.Load(), scoped.Load(), actions.Load())
	}
}
