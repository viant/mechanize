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

func TestBrowserStatusMCPClosedAuthenticatedReadOnly(t *testing.T) {
	p, err := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:observe"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID = "verified-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	runtime, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("browser status dispatched input")
		return automation.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	callbackFailure := false
	want := chrome.BrowserStatus{Available: true, Channels: []chrome.BrowserChannelStatus{{TrustScope: chrome.TrustScopeDesktop, Connected: true, ProcessQualified: true, ScopeQualified: true, AttentionCode: "inventoryUnavailable", UnknownCount: 1}}}
	s, err := New(Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, BrowserStatus: func(c context.Context, actor auth.Principal) (chrome.BrowserStatus, error) {
		calls++
		actual, err := auth.FromContext(c)
		if err != nil || !reflect.DeepEqual(actual, p) || !reflect.DeepEqual(actor, p) {
			t.Fatal("diagnostic principal changed")
		}
		if callbackFailure {
			return chrome.BrowserStatus{}, errors.New("private credential payload")
		}
		return want, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	client := s.AsClient(ctx)
	if _, err = client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range listed.Tools {
		if tool.Name == "mechanize_browser_status" {
			found = true
			raw, _ := json.Marshal(tool.InputSchema)
			if !strings.Contains(string(raw), `"additionalProperties":false`) {
				t.Fatal("status schema not closed")
			}
		}
	}
	if !found {
		t.Fatal("status tool not advertised")
	}
	for _, field := range []string{"namespace", "scope", "grantId", "sessionId", "credential", "private-credential-field"} {
		out, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_browser_status", Arguments: map[string]any{field: "private credential payload"}})
		if err == nil && (out == nil || out.IsError == nil || !*out.IsError) {
			t.Fatalf("caller override %s admitted", field)
		}
		if calls != 0 {
			t.Fatal("invalid input reached host status")
		}
		raw, _ := json.Marshal(out)
		if strings.Contains(string(raw), "private credential payload") || strings.Contains(string(raw), "private-credential-field") {
			t.Fatal("status error echoed payload")
		}
	}
	oversized, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_browser_status", Arguments: map[string]any{"scope": strings.Repeat("private credential payload", 100)}})
	if err == nil && (oversized == nil || oversized.IsError == nil || !*oversized.IsError) || calls != 0 {
		t.Fatal("oversized status input reached callback")
	}
	out, err := client.CallTool(context.Background(), &schema.CallToolRequestParams{Name: "mechanize_browser_status", Arguments: map[string]any{}})
	if err == nil && (out == nil || out.IsError == nil || !*out.IsError) {
		t.Fatal("missing principal status admitted")
	}
	if calls != 0 {
		t.Fatal("missing principal reached callback")
	}
	out, err = client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_browser_status", Arguments: map[string]any{}})
	if err != nil || out == nil || out.IsError != nil && *out.IsError || calls != 1 {
		t.Fatalf("owned status failed: %+v %v", out, err)
	}
	raw, _ := json.Marshal(out.StructuredContent)
	var got chrome.BrowserStatus
	if err = json.Unmarshal(raw, &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("diagnostic changed: %s %v", raw, err)
	}
	want = chrome.BrowserStatus{Available: false, Channels: []chrome.BrowserChannelStatus{}}
	out, err = client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_browser_status", Arguments: map[string]any{}})
	if err != nil || out == nil || out.IsError != nil && *out.IsError || out.StructuredContent.(map[string]any)["available"] != false {
		t.Fatal("missing Chrome callback status was not reported unavailable")
	}
	callbackFailure = true
	out, err = client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_browser_status", Arguments: map[string]any{}})
	if err != nil || out == nil || out.IsError == nil || !*out.IsError {
		t.Fatal("private status failure reported success")
	}
	raw, _ = json.Marshal(out)
	if strings.Contains(string(raw), "private credential payload") {
		t.Fatal("host status error exposed private payload")
	}
}
