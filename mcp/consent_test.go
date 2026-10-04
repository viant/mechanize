package mcp

import (
	"context"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	server "github.com/viant/mcp/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"testing"
)

func TestPermissionToolCannotDecideOrAutoGrant(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "human", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	called := 0
	handler := protocol.WithDefaultHandler(ctx, func(base *protocol.DefaultHandler) error {
		return RegisterConsent(base, func(_ context.Context, actual auth.Principal, session string, in consent.RequestInput) (consent.Request, error) {
			if actual.Namespace != p.Namespace || session != "owned" || in.Purpose != "Inspect draft" {
				t.Fatal("request context mismatch")
			}
			called++
			return consent.Request{ID: "request-only"}, nil
		})
	})
	s, e := server.New(server.WithNewHandler(handler))
	if e != nil {
		t.Fatal(e)
	}
	c := s.AsClient(ctx)
	if _, e = c.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	list, e := c.ListTools(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, tool := range list.Tools {
		if tool.Name != "mechanize_permission_request" {
			t.Fatalf("unexpected requester authority: %s", tool.Name)
		}
	}
	result, e := c.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_permission_request", Arguments: map[string]any{"sessionId": "owned", "scope": map[string]any{"kind": "application", "bundleID": "fixture"}, "modes": []string{"observe"}, "purpose": "Inspect draft", "durationSeconds": 60}})
	if e != nil {
		t.Fatal(e)
	}
	body := result.StructuredContent.(map[string]any)
	if called != 1 || body["code"] != "permissionRequired" || body["requestID"] != "request-only" || body["dispatchState"] != "notDispatched" {
		t.Fatalf("unexpected request result: %+v", body)
	}
	if body["grantID"] != nil {
		t.Fatal("request automatically granted")
	}
}
