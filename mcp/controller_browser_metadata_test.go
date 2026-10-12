package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
)

func TestControllerBrowserHelpersUseCanonicalClosedContracts(t *testing.T) {
	calls := map[string]int{}
	malformed := false
	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
		deps.BrowserActivateTab = func(_ context.Context, _ auth.Principal, in BrowserActivateTabInput) (BrowserActivateTabResult, error) {
			calls["activate"]++
			reason := "none"
			if malformed {
				reason = "PRIVATE_CANARY"
			}
			return BrowserActivateTabResult{Outcome: "activated", Reason: reason, RunID: "run", OperationID: "op"}, nil
		}
		deps.BrowserLocationMatches = func(_ context.Context, _ auth.Principal, origin string) (chrome.FocusedOriginMatch, error) {
			calls["focused"]++
			reason := "none"
			if malformed {
				reason = "PRIVATE_CANARY"
			}
			return chrome.FocusedOriginMatch{Available: true, MatchesExpectedOrigin: true, TabHandle: "p/b/7", Evidence: "extensionLastActiveTab", Reason: reason}, nil
		}
		deps.BrowserTabLocationMatches = func(_ context.Context, _ auth.Principal, in BrowserTabLocationMatchesInput) (chrome.TabLocationMatch, error) {
			calls["exact"]++
			reason := "none"
			if malformed {
				reason = "PRIVATE_CANARY"
			}
			return chrome.TabLocationMatch{Available: true, MatchesExpectedOrigin: true, PathChecked: in.ExpectedPath != "", MatchesExpectedPath: in.ExpectedPath != "", Reason: reason}, nil
		}
	})
	catalog, e := d.ListTools(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	listed := map[string]bool{}
	for _, tool := range catalog.Tools {
		listed[tool.Name] = true
	}
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "metadata"}))["sessionId"].(string)
	cases := []struct {
		name, key string
		args      map[string]any
	}{
		{"mechanize_browser_activate_tab", "activate", map[string]any{"sessionId": session, "clientRequestId": "show", "origin": "https://fixture.test", "tabHandle": "p/b/7"}},
		{"mechanize_browser_location_matches", "focused", map[string]any{"sessionId": session, "expectedOrigin": "https://fixture.test"}},
		{"mechanize_browser_tab_location_matches", "exact", map[string]any{"sessionId": session, "tabHandle": "p/b/7", "expectedOrigin": "https://fixture.test", "expectedPath": "/public"}},
	}
	for _, tc := range cases {
		if !listed[tc.name] {
			t.Fatal("canonical helper omitted", tc.name)
		}
		out := controllerCall(t, d, ctx, id, tc.name, tc.args)
		if out.IsError != nil && *out.IsError || calls[tc.key] != 1 {
			t.Fatal("valid helper refused", tc.name)
		}
		raw, _ := json.Marshal(out)
		if strings.Contains(string(raw), "https://") || strings.Contains(string(raw), "/public") {
			t.Fatal("actual route leaked")
		}
		before := calls[tc.key]
		tc.args["sessionId"] = "foreign"
		out = controllerCall(t, d, ctx, id, tc.name, tc.args)
		if out.IsError == nil || !*out.IsError || calls[tc.key] != before {
			t.Fatal("foreign session reached helper")
		}
		tc.args["sessionId"] = session
		tc.args["actualURL"] = "PRIVATE_CANARY"
		out = controllerCall(t, d, ctx, id, tc.name, tc.args)
		if out.IsError == nil || !*out.IsError || calls[tc.key] != before {
			t.Fatal("unclosed args reached helper")
		}
		delete(tc.args, "actualURL")
		malformed = true
		out = controllerCall(t, d, ctx, id, tc.name, tc.args)
		raw, _ = json.Marshal(out)
		if out.IsError == nil || !*out.IsError || strings.Contains(string(raw), "PRIVATE_CANARY") {
			t.Fatal("malformed private result escaped")
		}
		malformed = false
	}
}
