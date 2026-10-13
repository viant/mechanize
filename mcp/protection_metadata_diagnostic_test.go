package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestControllerProtectionMetadataFailureRetainsClosedCause(t *testing.T) {
	for _, test := range []struct{ phase, cause, expectedPhase, expectedCause string }{
		{"bind", "metadataSourceUnavailable", "bind", "metadataSourceUnavailable"},
		{"projection", "projectionCapacityExceeded", "projection", "projectionCapacityExceeded"},
		{"scopeList", "metadataSourceChanged", "scopeList", "metadataSourceChanged"},
		{"PRIVATE_CANARY", "PRIVATE_CANARY", "unknown", "metadataUnavailable"},
		{"projection", "PRIVATE_CANARY", "projection", "metadataUnavailable"},
	} {
		t.Run(test.expectedPhase+test.cause, func(t *testing.T) {
			calls := 0
			d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
				deps.Policy = func(context.Context, auth.Principal) (script.Policy, error) {
					return script.Policy{AllowAllWeb: true}, nil
				}
				deps.Observe = func(context.Context, auth.Principal, model.Surface) (model.Observation, error) {
					calls++
					return model.Observation{}, errors.Join(
						&model.MechanizeError{Code: "protectionMetadataUnavailable", Message: "Browser protection metadata is unavailable.", Stage: "admission", DispatchState: "notDispatched", EffectState: "none"},
						&durable.ProtectionMetadataFailure{Phase: test.phase, Cause: test.cause, Err: errors.New("PRIVATE_CANARY")})
				}
			})
			session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
			out := controllerCall(t, d, ctx, id, "mechanize_observe", map[string]any{"sessionId": session, "purpose": "Inspect visible interface", "surface": model.Surface{Kind: "web", Origin: "https://public.invalid"}})
			body := controllerBody(t, out)
			if out.IsError == nil || !*out.IsError || body["code"] != "protectionMetadataUnavailable" || body["dispatchState"] != "notDispatched" || body["metadataPhase"] != test.expectedPhase || body["metadataCause"] != test.expectedCause || calls != 1 {
				t.Fatal("canonical controller lost finite metadata cause", body)
			}
			wire, _ := json.Marshal(out)
			for _, forbidden := range []string{"PRIVATE_CANARY", "vault key", "review local permissions"} {
				if strings.Contains(string(wire), forbidden) {
					t.Fatal("metadata failure leaked details or invented permission guidance")
				}
			}
		})
	}
}
