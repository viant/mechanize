package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestNativeObservationFailureKeepsUsefulCauseThroughController(t *testing.T) {
	for _, code := range []string{"incompleteObservation", "staleFocus", "staleReference", "staleEpoch", "PRIVATE_CANARY", "deadline"} {
		t.Run(code, func(t *testing.T) {
			var cause error = &native.NativeError{Code: code, Message: "PRIVATE_CANARY", Stage: "PRIVATE_CANARY"}
			want := code
			if code == "PRIVATE_CANARY" {
				want = "nativeObservationUnavailable"
			}
			if code == "deadline" {
				cause = context.DeadlineExceeded
				want = "observationTimeout"
			}
			cause = fmt.Errorf("PRIVATE_CANARY: %w", cause)
			direct, rpc := observationFailure(cause)
			if rpc != nil {
				t.Fatal(rpc)
			}
			d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
				deps.Policy = func(context.Context, auth.Principal) (script.Policy, error) {
					return script.Policy{AllowAllNative: true}, nil
				}
				deps.Observe = func(context.Context, auth.Principal, model.Surface) (model.Observation, error) {
					return model.Observation{}, cause
				}
			})
			session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
			out := controllerCall(t, d, ctx, id, "mechanize_observe", map[string]any{"sessionId": session, "purpose": "Inspect current interface", "surface": model.Surface{Kind: "native", BundleID: "com.example.Fixture"}})
			body, original := controllerBody(t, out), controllerBody(t, direct)
			if out.IsError == nil || !*out.IsError || body["code"] != want || body["dispatchState"] != "notDispatched" || body["message"] != original["message"] {
				t.Fatal("native read diagnosis lost across browser transport", body, original)
			}
			for _, response := range []any{out, direct} {
				wire, _ := json.Marshal(response)
				if strings.Contains(string(wire), "PRIVATE_CANARY") || strings.Contains(string(wire), "permissionRequired") {
					t.Fatal("read diagnosis leaked raw data or invented permission requirement")
				}
			}
		})
	}
}
