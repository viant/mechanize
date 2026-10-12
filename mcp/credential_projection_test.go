package mcp

import (
	"context"
	"encoding/json"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"reflect"
	"strings"
	"testing"
)

func TestCredentialDiagnosticPublicMCPStructuredAndTextProjection(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "projection-owner", []string{"desktop:control"})
	p.ClientID = "projection-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	runtime, e := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("ordinary executor invoked")
		return automation.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	want := CredentialResult{PreparationID: strings.Repeat("a", 64), State: "needsNativeAction", Stage: "unavailable"}
	calls := 0
	callback := func(context.Context, auth.Principal, CredentialRefInput) (CredentialResult, error) {
		calls++
		return want, nil
	}
	server, e := New(Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, CredentialStatus: callback, CredentialApply: callback, CredentialPrepare: func(context.Context, auth.Principal, CredentialPrepareInput) (CredentialResult, error) {
		calls++
		return want, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	client := server.AsClient(ctx)
	if _, e = client.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	request := func(name string) *schema.CallToolResult {
		t.Helper()
		args := map[string]any{"sessionId": "owned-session", "preparationId": strings.Repeat("a", 64)}
		if name == "mechanize_credential_prepare" {
			args = map[string]any{"sessionId": "owned-session", "purpose": "login", "surface": map[string]any{"kind": "web", "origin": "https://fixture.invalid"}}
		}
		out, e := client.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: args})
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	check := func(name string) {
		t.Helper()
		before := calls
		out := request(name)
		if calls != before+1 || out.IsError != nil && *out.IsError {
			t.Fatalf("closed result rejected: %s", want.AttentionCode)
		}
		raw, _ := json.Marshal(out.StructuredContent)
		var actual CredentialResult
		if json.Unmarshal(raw, &actual) != nil || !reflect.DeepEqual(actual, want) {
			t.Fatal("structured projection changed", string(raw))
		}
		if len(out.Content) != 1 {
			t.Fatal("unexpected public content")
		}
		raw, _ = json.Marshal(out.Content[0])
		var text schema.TextContent
		if json.Unmarshal(raw, &text) != nil {
			t.Fatal("text unavailable")
		}
		actual = CredentialResult{}
		if json.Unmarshal([]byte(text.Text), &actual) != nil || !reflect.DeepEqual(actual, want) {
			t.Fatal("text projection changed")
		}
	}
	for _, code := range chrome.CredentialInspectionAttentionCodes() {
		want.AttentionCode = code
		want.Stage = "unavailable"
		if code == "privateInspectionChallenge" {
			want.Stage = "challenge"
		}
		check("mechanize_credential_status")
	}
	for _, code := range []string{"scopeChanged", "scopeSourcePresent", "scopeTargetProtected", "scopeInventoryUnavailable", "scopeLimit", "scopeUnsupported", "scopePreflightBusy", "scopeUnavailable", "scopeOtherLoginHeld", "sourceScopePersistence", "scopeSourceRetirement"} {
		want.AttentionCode = code
		want.Stage = ""
		check("mechanize_credential_status")
	}
	want = CredentialResult{State: "needsNativeAction"}
	for _, code := range []string{"scopeChanged", "scopeSourcePresent", "scopeTargetProtected", "scopeInventoryUnavailable", "scopeLimit", "scopeUnsupported", "scopePreflightBusy", "scopeUnavailable", "scopeOtherLoginHeld"} {
		want.AttentionCode = code
		check("mechanize_credential_prepare")
		out := request("mechanize_credential_status")
		if out.IsError == nil || !*out.IsError {
			t.Fatal("status accepted missing preparation")
		}
	}
	for _, bad := range []CredentialResult{{State: "ready", AttentionCode: "scopeUnavailable"}, {State: "needsNativeAction", AttentionCode: "scopeUnavailable", Stage: "challenge"}, {State: "needsNativeAction", AttentionCode: "scopeUnavailable", DispatchState: "notDispatched"}, {State: "needsNativeAction", AttentionCode: "privateInspectionHiddenChallengeControl"}, {State: "needsNativeAction", AttentionCode: "scopeUnavailable", Surface: &model.Surface{Kind: "web", Origin: "https://fixture.invalid", TabID: "profile/browser/7"}}, {PreparationID: strings.Repeat("a", 64), State: "needsNativeAction", AttentionCode: "privateInspectionPRIVATE_CANARY"}, {PreparationID: strings.Repeat("a", 64), State: "needsNativeAction", AttentionCode: "scopeUnavailable PRIVATE_CANARY"}} {
		want = bad
		out := request("mechanize_credential_prepare")
		raw, _ := json.Marshal(out)
		if out.IsError == nil || !*out.IsError || strings.Contains(string(raw), "PRIVATE_CANARY") {
			t.Fatal("unsafe result admitted or echoed")
		}
	}
}
