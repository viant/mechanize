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

func TestControllerPublicReadFailuresKeepFiniteOperationalReason(t *testing.T) {
	for _, code := range []string{"publicReadIdentityChanged", "publicReadInventoryUnavailable", "publicReadBusy", "publicReadLimit", "publicReadUnavailable"} {
		t.Run(code, func(t *testing.T) {
			calls := 0
			d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
				deps.Policy = func(context.Context, auth.Principal) (script.Policy, error) {
					return script.Policy{AllowAllWeb: true}, nil
				}
				deps.Observe = func(context.Context, auth.Principal, model.Surface) (model.Observation, error) {
					calls++
					return model.Observation{}, &model.MechanizeError{Code: code, Message: "PRIVATE_CANARY renderer internals", Stage: "admission", DispatchState: "notDispatched", EffectState: "none"}
				}
			})
			session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
			out := controllerCall(t, d, ctx, id, "mechanize_observe", map[string]any{"sessionId": session, "purpose": "Read public fixture", "surface": model.Surface{Kind: "web", Origin: "https://fixture.test"}})
			body := controllerBody(t, out)
			if out.IsError == nil || !*out.IsError || body["code"] != code || body["dispatchState"] != "notDispatched" || calls != 1 {
				t.Fatal("operational failure lost", body)
			}
			raw, _ := json.Marshal(out)
			if strings.Contains(string(raw), "PRIVATE_CANARY") || strings.Contains(string(raw), "review local permissions") || strings.Contains(string(raw), "privateDOMUnavailable") {
				t.Fatal("operational failure exposed details or requested approval")
			}
		})
	}
}
