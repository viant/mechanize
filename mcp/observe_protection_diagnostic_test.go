package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/vault"
)

func TestControllerProtectedObservationExplainsNativeFallback(t *testing.T) {
	calls := 0
	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
		deps.Policy = func(context.Context, auth.Principal) (script.Policy, error) {
			return script.Policy{AllowAllNative: true, AllowAllWeb: true}, nil
		}
		deps.Observe = func(_ context.Context, _ auth.Principal, s model.Surface) (model.Observation, error) {
			calls++
			if s.Kind == "web" {
				return model.Observation{}, fmt.Errorf("PRIVATE_CANARY: %w", vault.ErrDeliveryProtected)
			}
			return model.Observation{Surface: s}, nil
		}
	})
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
	args := map[string]any{"sessionId": session, "purpose": "Inspect visible interface", "surface": model.Surface{Kind: "web", Origin: "https://fixture.test"}}
	out := controllerCall(t, d, ctx, id, "mechanize_observe", args)
	body := controllerBody(t, out)
	if out.IsError == nil || !*out.IsError || body["code"] != "privateDOMUnavailable" || body["dispatchState"] != "notDispatched" || body["message"] != privateDOMMessage || calls != 1 {
		t.Fatal("protected observation lost native fallback guidance", body)
	}
	wire, _ := json.Marshal(out)
	if strings.Contains(string(wire), "PRIVATE_CANARY") || strings.Contains(string(wire), "review local permissions") {
		t.Fatal("private exception leaked or permission prompt introduced")
	}
	args["surface"] = model.Surface{Kind: "native", BundleID: "com.example.Fixture"}
	out = controllerCall(t, d, ctx, id, "mechanize_observe", args)
	if out.IsError != nil && *out.IsError || calls != 2 {
		t.Fatal("native observation incorrectly inherited web protection")
	}
}
