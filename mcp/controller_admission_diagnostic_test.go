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
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
)

func TestControllerTabsAndConsentDistinguishSurfaceScopeAndPermission(t *testing.T) {
	calls, requests := 0, 0
	var failure error
	d, id, ctx, _ := controllerFixture(t, func(deps *Dependencies) {
		deps.BrowserTabs = func(_ context.Context, _ auth.Principal, s model.Surface) (chrome.TabHandleInventory, error) {
			calls++
			return chrome.TabHandleInventory{Tabs: []chrome.TabHandle{{Handle: "p/b/7", Origin: s.Origin}}, Complete: true}, failure
		}
		deps.PermissionRequest = func(_ context.Context, _ auth.Principal, _ string, in consent.RequestInput) (consent.Request, error) {
			requests++
			return consent.Request{ID: "request-fixture"}, nil
		}
	})
	opened := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{"name": "fixture"}))
	session := opened["sessionId"].(string)
	args := map[string]any{"sessionId": session, "purpose": "Inspect public UI", "surface": map[string]any{"kind": "web", "origin": "https://fixture.test"}}
	assertCode := func(tool string, args any, want string) {
		t.Helper()
		out := controllerCall(t, d, ctx, id, tool, args)
		body := controllerBody(t, out)
		if body["code"] != want || body["dispatchState"] != "notDispatched" {
			t.Fatalf("%s: %v", tool, body)
		}
		wire, _ := json.Marshal(out)
		if strings.Contains(string(wire), "PRIVATE_CANARY") {
			t.Fatal("raw error escaped")
		}
	}
	out := controllerCall(t, d, ctx, id, "mechanize_browser_tabs", args)
	if out.IsError != nil && *out.IsError || calls != 1 {
		t.Fatal("valid web surface rejected", out)
	}
	for _, code := range []string{"permissionRequired", "permissionExpired", "permissionDenied"} {
		failure = &model.MechanizeError{Code: code, Message: "PRIVATE_CANARY", DispatchState: "notDispatched"}
		assertCode("mechanize_browser_tabs", args, code)
	}
	failure = errors.New("PRIVATE_CANARY")
	assertCode("mechanize_browser_tabs", args, "browserInventoryUnavailable")
	before := calls
	args["sessionId"] = "foreign"
	assertCode("mechanize_browser_tabs", args, "sessionNotOwned")
	args["sessionId"] = session
	args["surface"] = map[string]any{"kind": "chrome", "origin": "https://fixture.test"}
	assertCode("mechanize_browser_tabs", args, "invalidSurface")
	args["extra"] = "PRIVATE_CANARY"
	assertCode("mechanize_browser_tabs", args, "invalidArguments")
	if calls != before {
		t.Fatal("invalid request reached inventory")
	}
	request := map[string]any{"sessionId": session, "purpose": "Inspect public UI", "scope": map[string]any{"kind": "web", "origin": "https://fixture.test"}, "modes": []string{"observe"}, "durationSeconds": 60}
	assertCode("mechanize_permission_request", request, "invalidScopeKind")
	request["scope"] = map[string]any{"kind": "origin", "origin": "https://fixture.test/path"}
	assertCode("mechanize_permission_request", request, "invalidConsentScope")
	request["scope"] = map[string]any{"kind": "origin", "origin": "https://fixture.test"}
	request["modes"] = []string{"click"}
	assertCode("mechanize_permission_request", request, "unsupportedMode")
	if requests != 0 {
		t.Fatal("invalid consent reached service")
	}
	request["modes"] = []string{"observe"}
	assertCode("mechanize_permission_request", request, "permissionRequired")
	if requests != 1 {
		t.Fatal("valid exact-origin request did not reach service")
	}
}

func TestDiscoverySchemasDistinguishSurfaceAndConsentKinds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input any
		field string
		want  []string
	}{{"observe", (*ObserveInput)(nil), "surface", []string{"web", "native"}}, {"tabs", (*BrowserTabsInput)(nil), "surface", []string{"web", "native"}}, {"consent", (*ConsentRequestInput)(nil), "scope", []string{"origin", "application", "window", "browser", "desktop"}}} {
		var input schema.ToolInputSchema
		if err := input.Load(tc.input); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(input)
		var wire map[string]any
		if json.Unmarshal(raw, &wire) != nil {
			t.Fatal("invalid schema")
		}
		properties := wire["properties"].(map[string]any)
		field := properties[tc.field].(map[string]any)
		kind := field["properties"].(map[string]any)["kind"].(map[string]any)
		actual, _ := kind["enum"].([]any)
		if len(actual) != len(tc.want) {
			t.Fatalf("%s missing kind enum: %s", tc.name, raw)
		}
		for i, want := range tc.want {
			if actual[i] != want {
				t.Fatalf("%s wrong kind enum: %v", tc.name, actual)
			}
		}
	}
}
