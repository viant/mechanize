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

func TestTabLocationMCPRejectsPrivateURLsAndPublishesOnlyClosedComparison(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:observe"})
	p.ClientID = "tab-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	rt, e := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("metadata sent input")
		return automation.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	session, e := rt.Open(ctx, "tab comparison")
	if e != nil {
		t.Fatal(e)
	}
	defer rt.Close(ctx, session.SessionID)
	calls := 0
	want := chrome.TabLocationMatch{Available: true, MatchesExpectedOrigin: true, PathChecked: true, MatchesExpectedPath: true, Reason: "none"}
	s, e := New(Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, BrowserTabLocationMatches: func(c context.Context, actor auth.Principal, in BrowserTabLocationMatchesInput) (chrome.TabLocationMatch, error) {
		calls++
		if actor.ClientID != p.ClientID || in.TabHandle != "profile/browser/7" || in.ExpectedPath != "/connect/Login/error" {
			t.Fatal("target changed")
		}
		return want, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	client := s.AsClient(ctx)
	if _, e = client.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	args := map[string]any{"sessionId": session.SessionID, "tabHandle": "profile/browser/7", "expectedOrigin": "https://fixture.test", "expectedPath": "/connect/Login/error"}
	call := func(a map[string]any) *schema.CallToolResult {
		out, e := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_browser_tab_location_matches", Arguments: a})
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	out := call(args)
	if out.IsError != nil && *out.IsError {
		t.Fatal(out)
	}
	raw, _ := json.Marshal(out.StructuredContent)
	var got chrome.TabLocationMatch
	if json.Unmarshal(raw, &got) != nil || got != want {
		t.Fatal("comparison changed")
	}
	for key, value := range map[string]any{"sessionId": "foreign", "tabHandle": "https://PRIVATE_CANARY/", "expectedOrigin": "https://PRIVATE_CANARY@fixture.test", "expectedPath": "/login?PRIVATE_CANARY", "unknown": "PRIVATE_CANARY"} {
		bad := map[string]any{}
		for k, v := range args {
			bad[k] = v
		}
		bad[key] = value
		out = call(bad)
		encoded, _ := json.Marshal(out)
		if out.IsError == nil || !*out.IsError || calls != 1 || strings.Contains(string(encoded), "PRIVATE_CANARY") {
			t.Fatal("invalid input reached reader or escaped")
		}
	}
	want.Reason = "PRIVATE_CANARY"
	out = call(args)
	encoded, _ := json.Marshal(out)
	if out.IsError == nil || !*out.IsError || strings.Contains(string(encoded), "PRIVATE_CANARY") {
		t.Fatal("unreviewed output exposed")
	}
}

func TestBrowserComparisonPathAndResultContract(t *testing.T) {
	for _, p := range []string{"", "/", "/connect/Login/error"} {
		if !ValidBrowserComparisonPath(p) {
			t.Fatal("public path rejected", p)
		}
	}
	for _, p := range []string{"https://fixture.test/a", "//foreign/a", "/a?token=x", "/a#password", "/a/../secret", "/a\\b"} {
		if ValidBrowserComparisonPath(p) {
			t.Fatal("noncanonical path accepted")
		}
	}
	for _, v := range []chrome.TabLocationMatch{{Reason: "tabUnavailable", PathChecked: true}, {Available: true, Reason: "none", MatchesExpectedPath: true}, {Available: true, Reason: "authorityChanged"}} {
		if tabLocationResultValid(v) {
			t.Fatal("invalid comparison state")
		}
	}
}
