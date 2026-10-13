package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"strings"
	"testing"
	"time"
)

func TestOperationStatusTypedFailureReachesController(t *testing.T) {
	testOperationFailureRoundTrip(t, &model.MechanizeError{Code: "playwrightTargetChanged", Message: "PRIVATE_DIAGNOSTIC_CANARY", DispatchState: "notDispatched"}, "playwrightTargetChanged", "notDispatched")
}

func TestOperationStatusBindingFailureReachesController(t *testing.T) {
	testOperationFailureRoundTrip(t, &model.MechanizeError{Code: "bindingUnconfirmed", Stage: "browser", DispatchState: "notDispatched", EffectState: "none", Message: "PRIVATE_DIAGNOSTIC_CANARY"}, "bindingUnconfirmed", "notDispatched")
}

type nativeOperationFailureFixture struct{ code, state string }

func (e nativeOperationFailureFixture) Error() string {
	return "PRIVATE_DIAGNOSTIC_CANARY key/text https://private.test/?secret=fixture"
}
func (e nativeOperationFailureFixture) NativeExecutionFailure() (string, string, bool) {
	return e.code, e.state, true
}
func TestOperationStatusQualifiedNativeFailureReachesController(t *testing.T) {
	for _, state := range []string{"notDispatched", "unknown"} {
		t.Run(state, func(t *testing.T) {
			testOperationFailureRoundTrip(t, nativeOperationFailureFixture{"foregroundRaiseWindowMissing", state}, "foregroundRaiseWindowMissing", state)
		})
	}
}
func TestOperationStatusQualifiedAXRecipientFailuresRemainClosed(t *testing.T) {
	for _, code := range []string{"foregroundAXWindowUnavailable", "foregroundAXWindowChanged", "foregroundAXOwnerMismatch", "foregroundAXFocusUnavailable", "foregroundAXFocusChanged", "foregroundGeometryUnavailable", "foregroundGeometryUnbound", "foregroundGeometryAmbiguous"} {
		for _, state := range []string{"notDispatched", "unknown"} {
			t.Run(code+"/"+state, func(t *testing.T) {
				testOperationFailureRoundTrip(t, nativeOperationFailureFixture{code, state}, code, state)
			})
		}
	}
}

func testOperationFailureRoundTrip(t *testing.T, provided error, wantCode, wantState string) {
	p, _ := auth.NewPrincipal("fixture", "", "typed-failure", []string{"desktop:observe", "desktop:control"})
	p.ClientID = "controller:failure"
	ctx := auth.WithPrincipal(context.Background(), p)
	r, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		return automation.StepResult{DispatchState: wantState, VerificationState: "unknown"}, fmt.Errorf("private wrapper: %w", provided)
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := script.Policy{AllowedSurfaces: map[string]bool{"com.example.Fixture": true}, AllowMutation: true, Capabilities: map[string]bool{"native:semanticPress": true, "native:idLocator": true}}
	gateway, err := New(Dependencies{Runtime: r, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return policy, nil }})
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewControllerDispatcher(gateway, r)
	if err != nil {
		t.Fatal(err)
	}
	id := chrome.ControllerIdentity{Principal: p, ConversationID: "fixture", Origin: "https://shell.fixture.test", DocumentID: "fixture-doc"}
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "failure"}))["sessionId"].(string)
	defer d.CloseController(ctx, id)
	started := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_step_run", map[string]any{"sessionId": session, "clientRequestId": "one-failure", "source": `app("com.example.Fixture").getById("save").click()`}))
	operation := started["operationId"].(string)
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = r.Wait(bounded, session, operation); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"sessionId": session, "operationId": operation}
	projected := controllerCall(t, d, ctx, id, "mechanize_operation_status", args)
	direct := gateway.AsClient(ctx)
	if _, err = direct.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := direct.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_operation_status", Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []*schema.CallToolResult{projected, raw} {
		body := controllerBody(t, out)
		failure, ok := body["executionFailure"].(map[string]any)
		if !ok || failure["code"] != wantCode || failure["dispatchState"] != wantState || len(failure) != expectedFailureFields(provided) {
			t.Fatalf("closed failure missing: %+v", body)
		}
		if expectedFailureFields(provided) == 3 {
			stats, ok := failure["playwright"].(map[string]any)
			if !ok || stats["peerMs"] != float64(30) || stats["lastMethod"] != "Runtime.callFunctionOn" || stats["phase"] != wantCode {
				t.Fatal("closed timing/phase lost")
			}
		}
		if body["operationId"] != operation || body["sessionId"] != session || body["verificationState"] == "verified" {
			t.Fatal("operation correlation/business status changed")
		}
		encoded, _ := json.Marshal(out)
		if strings.Contains(string(encoded), "PRIVATE_DIAGNOSTIC_CANARY") || strings.Contains(string(encoded), "private wrapper") {
			t.Fatal("raw failure text escaped")
		}
	}
	other := p
	other.ClientID = "other"
	denied, err := direct.CallTool(auth.WithPrincipal(ctx, other), &schema.CallToolRequestParams{Name: "mechanize_operation_status", Arguments: args})
	if err == nil && (denied.IsError == nil || !*denied.IsError) {
		t.Fatal("foreign client read failure")
	}
}

func expectedFailureFields(err error) int {
	if _, ok := err.(interface {
		PlaywrightExecutionDiagnostic() automation.PlaywrightDiagnostic
	}); ok {
		return 3
	}
	return 2
}

type playwrightOperationFailureFixture struct{ *model.MechanizeError }

func (e playwrightOperationFailureFixture) Unwrap() error { return e.MechanizeError }
func (e playwrightOperationFailureFixture) PlaywrightExecutionDiagnostic() automation.PlaywrightDiagnostic {
	return automation.PlaywrightDiagnostic{Phase: e.Code, Callbacks: 7, PeerChecks: 2, PeerMs: 30, IdentityChecks: 12, ElapsedMs: 80, LastCallback: "relay.send", LastMethod: "Runtime.callFunctionOn"}
}
func TestOperationStatusPlaywrightTimingReachesController(t *testing.T) {
	testOperationFailureRoundTrip(t, playwrightOperationFailureFixture{&model.MechanizeError{Code: "playwrightDeadline", Stage: "browser", DispatchState: "notDispatched", EffectState: "none", Message: "PRIVATE_DIAGNOSTIC_CANARY"}}, "playwrightDeadline", "notDispatched")
}
