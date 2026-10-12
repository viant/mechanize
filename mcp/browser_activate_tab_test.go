package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestBrowserActivateTabClosedMetadata(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	rt, e := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("projection dispatched input")
		return automation.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	session, e := rt.Open(ctx, "activation projection")
	if e != nil {
		t.Fatal(e)
	}
	defer rt.Close(ctx, session.SessionID)
	calls := 0
	want := BrowserActivateTabResult{Outcome: "pending", Reason: "tabActivationPending", RunID: "run", OperationID: "operation"}
	server, e := New(Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, BrowserActivateTab: func(_ context.Context, actor auth.Principal, in BrowserActivateTabInput) (BrowserActivateTabResult, error) {
		calls++
		if actor.ClientID != p.ClientID || in.TabHandle != "profile/browser/42" {
			t.Fatal("activation identity changed")
		}
		return want, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	client := server.AsClient(ctx)
	if _, e = client.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	args := map[string]any{"sessionId": session.SessionID, "clientRequestId": "request", "origin": "https://fixture.test", "tabHandle": "profile/browser/42"}
	call := func(c context.Context, a map[string]any) *schema.CallToolResult {
		t.Helper()
		r, e := client.CallTool(c, &schema.CallToolRequestParams{Name: "mechanize_browser_activate_tab", Arguments: a})
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	for _, out := range []BrowserActivateTabResult{want, {Outcome: "activated", Reason: "none", RunID: "run", OperationID: "operation"}, {Outcome: "unknown", Reason: "tabActivationUnknown", RunID: "run", OperationID: "operation"}, {Outcome: "notDispatched", Reason: "originDenied", RunID: "run", OperationID: "operation"}} {
		want = out
		r := call(ctx, args)
		if r.IsError != nil && *r.IsError {
			t.Fatal("closed outcome rejected", out)
		}
		body, _ := json.Marshal(r.StructuredContent)
		var got BrowserActivateTabResult
		if json.Unmarshal(body, &got) != nil || got != want {
			t.Fatal("closed metadata changed", string(body))
		}
	}
	before := calls
	for _, bad := range []map[string]any{nil, {}, {"sessionId": session.SessionID, "clientRequestId": "request", "origin": "https://fixture.test/path", "tabHandle": "profile/browser/42"}, {"sessionId": session.SessionID, "clientRequestId": "request", "origin": "https://fixture.test", "tabHandle": "https://PRIVATE_CANARY/"}, {"sessionId": session.SessionID, "clientRequestId": "request", "origin": "https://fixture.test", "tabHandle": "profile/browser/42", "grantId": "PRIVATE_CANARY"}, {"sessionId": "foreign-session", "clientRequestId": "request", "origin": "https://fixture.test", "tabHandle": "profile/browser/42"}} {
		r := call(ctx, bad)
		body, _ := json.Marshal(r)
		if r.IsError == nil || !*r.IsError || calls != before || strings.Contains(string(body), "PRIVATE_CANARY") {
			t.Fatal("invalid input reached callback", string(body))
		}
	}
	foreign := p
	foreign.ClientID = "other"
	if r := call(auth.WithPrincipal(context.Background(), foreign), args); r.IsError == nil || !*r.IsError || calls != before {
		t.Fatal("foreign session accepted")
	}
	for _, bad := range []BrowserActivateTabResult{{Outcome: "activated", Reason: "tabActivationPending", RunID: "run", OperationID: "operation"}, {Outcome: "unknown", Reason: "none", RunID: "run", OperationID: "operation"}, {Outcome: "pending", Reason: "PRIVATE_CANARY", RunID: "run", OperationID: "operation"}, {Outcome: "activated", Reason: "none"}} {
		want = bad
		r := call(ctx, args)
		body, _ := json.Marshal(r)
		if r.IsError == nil || !*r.IsError || strings.Contains(string(body), "PRIVATE_CANARY") {
			t.Fatal("invalid projection accepted", string(body))
		}
	}
}
