package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestBrowserTabsOwnedSessionClosedInputAndPrivateErrors(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:observe"})
	p.ClientID = "client-a"
	ctx := auth.WithPrincipal(context.Background(), p)
	rt, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("inventory dispatched input")
		return automation.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := rt.Open(ctx, "inventory")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	fail := false
	s, err := New(Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, BrowserTabs: func(c context.Context, actor auth.Principal, surface model.Surface) (chrome.TabHandleInventory, error) {
		calls++
		binding, ok := auth.ConsentBindingFromContext(c)
		if !ok || binding.SessionID != session.SessionID || binding.Purpose != "Select website tab" || actor.ClientID != p.ClientID {
			t.Fatal("inventory binding changed")
		}
		if fail {
			return chrome.TabHandleInventory{}, errors.New("private credential payload")
		}
		return chrome.TabHandleInventory{Tabs: []chrome.TabHandle{{Handle: "profile/browser/7", Origin: surface.Origin}}, Complete: true}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	client := s.AsClient(ctx)
	if _, err = client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"sessionId": session.SessionID, "purpose": "Select website tab", "surface": map[string]any{"kind": "web", "origin": "https://fixture.test"}}
	call := func(c context.Context, a map[string]any) *schema.CallToolResult {
		out, e := client.CallTool(c, &schema.CallToolRequestParams{Name: "mechanize_browser_tabs", Arguments: a})
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	out := call(ctx, args)
	if out.IsError != nil && *out.IsError || calls != 1 {
		t.Fatal("owned inventory rejected")
	}
	foreign := p
	foreign.ClientID = "client-b"
	out = call(auth.WithPrincipal(context.Background(), foreign), args)
	if out.IsError == nil || !*out.IsError || calls != 1 {
		t.Fatal("foreign session reached inventory")
	}
	extra := map[string]any{}
	for k, v := range args {
		extra[k] = v
	}
	extra["credential"] = "private credential payload"
	out = call(ctx, extra)
	if out.IsError == nil || !*out.IsError || calls != 1 {
		t.Fatal("unknown input reached inventory")
	}
	fail = true
	out = call(ctx, args)
	bytes, _ := json.Marshal(out)
	if out.IsError == nil || !*out.IsError || strings.Contains(string(bytes), "private credential payload") {
		t.Fatal("callback error exposed private content")
	}
}
