package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mechanize/backend/chrome"
)

func TestControllerDiscoveryUsesOnlyVerifiedPublicOrigin(t *testing.T) {
	for _, name := range []string{"mechanize_capabilities", "mechanize_describe"} {
		t.Run(name, func(t *testing.T) {
			d, id, ctx, mutations := controllerFixture(t)
			id.Origin = "http://localhost:3000"
			id.DocumentID = "PRIVATE_DOCUMENT_CANARY"
			id.ProfileChannel = "PRIVATE_PROFILE_CANARY"
			id.BrowserInstance = "PRIVATE_BROWSER_CANARY"
			body := controllerBody(t, controllerCall(t, d, ctx, id, name, map[string]any{}))
			surface, ok := body["controllerContext"].(map[string]any)
			if !ok || len(surface) != 2 || surface["kind"] != "web" || surface["origin"] != id.Origin {
				t.Fatal("missing verified web context", surface)
			}
			encoded, _ := json.Marshal(body)
			if strings.Contains(string(encoded), "PRIVATE_") || mutations.Load() != 0 {
				t.Fatal("discovery exposed private identity or mutated")
			}
			// Empty arguments are enforced before projection. A page cannot replace
			// broker-owned identity with a claimed origin or native application.
			for _, args := range []map[string]any{{"controllerContext": map[string]any{"kind": "native", "origin": "https://foreign.test"}}, {"origin": "https://foreign.test"}} {
				answer := controllerCall(t, d, ctx, id, name, args)
				if answer.IsError == nil || !*answer.IsError {
					t.Fatal("caller-supplied routing context accepted")
				}
			}
			foreign := id
			foreign.Principal.ClientID = "controller:foreign"
			if _, err := d.CallTool(ctx, foreign, chrome.ControllerToolCall{Name: name, Arguments: json.RawMessage(`{}`)}); err == nil {
				t.Fatal("foreign controller accepted")
			}
		})
	}
}

func TestControllerDiscoveryNeverProjectsNonOriginURL(t *testing.T) {
	for _, origin := range []string{"https://host.test/path", "https://host.test/?PRIVATE_QUERY_CANARY", "https://user:PRIVATE_PASSWORD_CANARY@host.test", "chrome://extensions", ""} {
		d, id, ctx, _ := controllerFixture(t)
		id.Origin = origin
		body := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_capabilities", map[string]any{}))
		if _, ok := body["controllerContext"]; ok {
			t.Fatal("non-origin context projected")
		}
		encoded, _ := json.Marshal(body)
		if strings.Contains(string(encoded), "PRIVATE_") {
			t.Fatal("private URL data exposed")
		}
	}
}
