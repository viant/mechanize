package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestBrowserLocationMatchesMCPClosedInputOwnedSessionAndOutput(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:observe"})
	p.ClientID = "client-a"
	ctx := auth.WithPrincipal(context.Background(), p)
	rt, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("comparison dispatched browser input")
		return automation.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := rt.Open(ctx, "origin comparison")
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx, session.SessionID)
	calls := 0
	want := chrome.FocusedOriginMatch{Available: true, MatchesExpectedOrigin: true, Reason: "none", WindowFocused: true, Evidence: "extensionFocusedTab", TabHandle: "profile/browser/7"}
	var callbackErr error
	s, err := New(Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, BrowserLocationMatches: func(c context.Context, actor auth.Principal, origin string) (chrome.FocusedOriginMatch, error) {
		calls++
		binding, ok := auth.ConsentBindingFromContext(c)
		if !ok || binding.SessionID != session.SessionID || binding.Purpose != focusedOriginPurpose || binding.GrantID != "" || actor.ClientID != p.ClientID || origin != "https://fixture.test" {
			t.Fatal("comparison authority changed")
		}
		return want, callbackErr
	}})
	if err != nil {
		t.Fatal(err)
	}
	client := s.AsClient(ctx)
	if _, err = client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	call := func(c context.Context, args map[string]any) *schema.CallToolResult {
		out, e := client.CallTool(c, &schema.CallToolRequestParams{Name: "mechanize_browser_location_matches", Arguments: args})
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	args := map[string]any{"sessionId": session.SessionID, "expectedOrigin": "https://fixture.test"}
	check := func(out *schema.CallToolResult) {
		t.Helper()
		if out.IsError != nil && *out.IsError {
			t.Fatal("comparison rejected", out)
		}
		raw, _ := json.Marshal(out.StructuredContent)
		var got chrome.FocusedOriginMatch
		if json.Unmarshal(raw, &got) != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("structured result changed: %s", raw)
		}
		var text schema.TextContent
		content, _ := json.Marshal(out.Content[0])
		got = chrome.FocusedOriginMatch{}
		if json.Unmarshal(content, &text) != nil || json.Unmarshal([]byte(text.Text), &got) != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("text result changed")
		}
	}
	check(call(ctx, args))
	for _, bad := range []map[string]any{
		nil, {}, {"sessionId": session.SessionID, "expectedOrigin": "https://fixture.test/"},
		{"sessionId": session.SessionID, "expectedOrigin": "https://user:PRIVATE_CANARY@fixture.test"},
		{"sessionId": session.SessionID, "expectedOrigin": "https://fixture.test?PRIVATE_CANARY"},
		{"sessionId": session.SessionID, "expectedOrigin": "chrome://settings"},
		{"sessionId": session.SessionID, "expectedOrigin": "https://fixture.test", "grantId": "PRIVATE_CANARY"},
		{"sessionId": session.SessionID, "expectedOrigin": "https://fixture.test", "purpose": "PRIVATE_CANARY"},
		{"sessionId": "foreign-session", "expectedOrigin": "https://fixture.test"},
	} {
		out := call(ctx, bad)
		raw, _ := json.Marshal(out)
		if out.IsError == nil || !*out.IsError || calls != 1 || strings.Contains(string(raw), "PRIVATE_CANARY") {
			t.Fatal("invalid input reached comparison or escaped", string(raw))
		}
	}
	foreign := p
	foreign.ClientID = "other-client"
	for _, c := range []context.Context{auth.WithPrincipal(context.Background(), foreign)} {
		out := call(c, args)
		if out.IsError == nil || !*out.IsError || calls != 1 {
			t.Fatal("foreign actor reached comparison")
		}
	}
	missing, missingErr := client.CallTool(context.Background(), &schema.CallToolRequestParams{Name: "mechanize_browser_location_matches", Arguments: args})
	if missingErr == nil && (missing == nil || missing.IsError == nil || !*missing.IsError) || calls != 1 {
		t.Fatal("missing principal reached comparison")
	}
	want = chrome.FocusedOriginMatch{Available: true, MatchesExpectedOrigin: true, Reason: "none", WindowFocused: false, Evidence: "extensionLastActiveTab", TabHandle: "profile/browser/7"}
	check(call(ctx, args))
	want = chrome.FocusedOriginMatch{Available: true, Reason: "none", WindowFocused: true, Evidence: "extensionFocusedTab"}
	check(call(ctx, args))
	for _, reason := range []string{"noFocusedWindow", "ambiguousFocusedTab", "permissionUnavailable", "tabUnavailable", "pendingNavigation", "unsafeTab", "unsupportedLocation", "authorityChanged", "transportUnavailable", "noQualifiedChannel", "unsupportedWorker"} {
		want = chrome.FocusedOriginMatch{Reason: reason}
		check(call(ctx, args))
	}
	callbackErr = errors.New("PRIVATE_CANARY")
	out := call(ctx, args)
	raw, _ := json.Marshal(out)
	if out.IsError == nil || !*out.IsError || strings.Contains(string(raw), "PRIVATE_CANARY") {
		t.Fatal("private callback failure leaked")
	}
	callbackErr = nil
	for _, bad := range []chrome.FocusedOriginMatch{
		{Reason: "PRIVATE_CANARY"},
		{Available: true, Reason: "none", Evidence: "PRIVATE_CANARY"},
		{Reason: "tabUnavailable", MatchesExpectedOrigin: true},
		{Available: true, Reason: "none", WindowFocused: true, Evidence: "extensionFocusedTab", TabHandle: "profile/browser/7"},
		{Available: true, MatchesExpectedOrigin: true, Reason: "none", WindowFocused: true, Evidence: "extensionFocusedTab", TabHandle: "https://PRIVATE_CANARY/"},
	} {
		want = bad
		out = call(ctx, args)
		raw, _ = json.Marshal(out)
		if out.IsError == nil || !*out.IsError || strings.Contains(string(raw), "PRIVATE_CANARY") {
			t.Fatal("unsafe comparison output exposed", string(raw))
		}
	}
}
