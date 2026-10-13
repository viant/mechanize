package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestControllerWebPredicateContractRejectedBeforeRuntime(t *testing.T) {
	d, id, ctx, dispatches := controllerFixture(t, func(deps *Dependencies) {
		deps.Policy = func(context.Context, auth.Principal) (script.Policy, error) {
			return script.Policy{AllowAllWeb: true, AllowMutation: true}, nil
		}
	})
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
	for _, mode := range []string{"id", "authority"} {
		plan, e := script.Compile(`web.tab(origin:"https://fixture.test").getById("message",exact:true).fill("Public fixture",timeout:3s)`)
		if e != nil {
			t.Fatal(e)
		}
		plan.Requires = &model.Requirements{Adapters: []string{"web"}}
		plan.Surfaces = map[string]model.Surface{"fixture": plan.Steps[0].Target.Surface}
		plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: mode}}
		inputs := map[string]model.Value{}
		for k, v := range map[string]string{"origin": "https://fixture.test", "strategy": "id", "selector": "message", "attribute": "value", "expected": "Public fixture"} {
			inputs[k] = model.Value{Kind: model.StringValue, String: v}
		}
		predicate := &model.Predicate{Kind: "adapter", Adapter: "web", Name: "valueEquals", Scope: model.PredicateScope{SurfaceRef: "fixture"}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "observational", Inputs: inputs}
		plan.Steps[0].Postcondition = predicate
		if mode == "id" {
			delete(inputs, "selector")
			inputs["id"] = model.Value{Kind: model.StringValue, String: "PRIVATE_CANARY"}
		} else {
			predicate.RequiredAuthority = "authoritative"
		}
		source, _ := json.Marshal(plan)
		for _, tool := range []string{"mechanize_script_validate", "mechanize_script_run"} {
			args := map[string]any{"source": string(source), "format": "json"}
			if tool == "mechanize_script_run" {
				args["sessionId"] = session
				args["clientRequestId"] = mode
				args["purpose"] = "Public contract test"
			}
			out := controllerCall(t, d, ctx, id, tool, args)
			body := controllerBody(t, out)
			if out.IsError == nil || !*out.IsError || body["code"] != "invalidPredicate" || body["dispatchState"] != "notDispatched" {
				t.Fatal("closed validation error lost", body)
			}
			raw, _ := json.Marshal(out)
			if strings.Contains(string(raw), "PRIVATE_CANARY") || strings.Contains(string(raw), "review local permissions") {
				t.Fatal("validation disclosed values or requested approval")
			}
		}
	}
	if dispatches.Load() != 0 {
		t.Fatal("invalid contract dispatched runtime action")
	}
}
