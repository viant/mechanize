package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestNativeMCPMaintenanceOwnedSessionStrictArgumentsAndControllerIsolation(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "native-maintenance", []string{"desktop:control"})
	p.ClientID = "development-agent"
	ctx := auth.WithPrincipal(context.Background(), p)
	rt, e := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("maintenance dispatched page/native input")
		return automation.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	opened, e := rt.Open(ctx, "maintenance")
	if e != nil {
		t.Fatal(e)
	}
	defer rt.Close(ctx, opened.SessionID)
	calls := 0
	callback := func(c context.Context, actor auth.Principal, in ExtensionMaintenanceInput) (chrome.ExtensionMaintenanceResult, error) {
		calls++
		actual, _ := auth.FromContext(c)
		if actor.ClientID != p.ClientID || actual.ClientID != p.ClientID || in.SessionID != opened.SessionID {
			t.Fatal("maintenance ownership changed")
		}
		return chrome.ExtensionMaintenanceResult{AttemptID: strings.Repeat("a", 64), Outcome: "unknown", Reason: "reloadRequested", DispatchState: "unknown"}, nil
	}
	server, e := New(Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, ExtensionReload: callback, ExtensionReloadStatus: callback})
	if e != nil {
		t.Fatal(e)
	}
	client := server.AsClient(ctx)
	if _, e = client.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	args := map[string]any{"sessionId": opened.SessionID, "clientRequestId": "original-request", "expectedVersion": "0.1.70"}
	for _, name := range []string{"mechanize_extension_reload", "mechanize_extension_reload_status"} {
		out, e := client.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: args})
		if e != nil || out.IsError != nil && *out.IsError {
			t.Fatal(out, e)
		}
	}
	if calls != 2 {
		t.Fatal("native maintenance callbacks missing")
	}
	for _, mode := range []string{"extra", "version", "session"} {
		bad := map[string]any{}
		for k, v := range args {
			bad[k] = v
		}
		if mode == "extra" {
			bad["extensionId"] = "PRIVATE_CANARY"
		}
		if mode == "version" {
			bad["expectedVersion"] = "PRIVATE_CANARY"
		}
		if mode == "session" {
			bad["sessionId"] = "foreign"
		}
		out, e := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_extension_reload", Arguments: bad})
		if e != nil || out.IsError == nil || !*out.IsError {
			t.Fatal("invalid maintenance admitted", out, e)
		}
		raw, _ := json.Marshal(out)
		if strings.Contains(string(raw), "PRIVATE_CANARY") {
			t.Fatal("raw arguments leaked")
		}
	}
	if calls != 2 {
		t.Fatal("invalid maintenance reached callback")
	}
	// The native registry can expose these endpoints; the page bridge cannot.
	dispatcher, e := NewControllerDispatcher(server, rt)
	if e != nil {
		t.Fatal(e)
	}
	browser := p
	browser.ClientID = "controller:fixture"
	browserCtx := auth.WithPrincipal(context.Background(), browser)
	identity := chrome.ControllerIdentity{Principal: browser, ConversationID: "controller", Origin: "https://shell.fixture.test", DocumentID: "document", CatalogToolLimit: 64}
	for _, name := range []string{"mechanize_extension_reload", "mechanize_extension_reload_status"} {
		raw, _ := json.Marshal(args)
		out, e := dispatcher.CallTool(browserCtx, identity, chrome.ControllerToolCall{Name: name, Arguments: raw})
		if e != nil || out.IsError == nil || !*out.IsError {
			t.Fatal("maintenance escaped to page controller", out, e)
		}
	}
	listed, e := dispatcher.ListTools(browserCtx, identity)
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := json.Marshal(listed)
	if strings.Contains(string(wire), "mechanize_extension_reload") {
		t.Fatal("native maintenance advertised to website")
	}
	if calls != 2 {
		t.Fatal("controller reached maintenance callback")
	}
}
