package mcp

import (
	"context"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	server "github.com/viant/mcp/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestObserveEnforcesKindAwareSurfaceScope(t *testing.T) {
	p, err := auth.NewPrincipal("fixture", "", "human", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		policy  script.Policy
		surface model.Surface
		allow   bool
	}{
		{"all native", script.Policy{AllowAllNative: true}, model.Surface{Kind: "native", BundleID: "com.example.app"}, true},
		{"all web", script.Policy{AllowAllWeb: true}, model.Surface{Kind: "web", Origin: "https://example.com"}, true},
		{"native cannot permit web", script.Policy{AllowAllNative: true}, model.Surface{Kind: "web", Origin: "https://example.com"}, false},
		{"explicit native", script.Policy{AllowedSurfaces: map[string]bool{"com.example.app": true}}, model.Surface{Kind: "native", BundleID: "com.example.app"}, true},
		{"empty native target", script.Policy{AllowAllNative: true}, model.Surface{Kind: "native"}, false},
		{"empty web target", script.Policy{AllowAllWeb: true}, model.Surface{Kind: "web"}, false},
		{"unknown kind", script.Policy{AllowedSurfaces: map[string]bool{"anything": true}, AllowAllNative: true, AllowAllWeb: true}, model.Surface{Kind: "other", BundleID: "anything"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := auth.WithPrincipal(context.Background(), p)
			observeCalls := 0
			handler := protocol.WithDefaultHandler(ctx, func(base *protocol.DefaultHandler) error {
				return registerObserve(base, Dependencies{
					Policy: func(context.Context, auth.Principal) (script.Policy, error) { return tc.policy, nil },
					Observe: func(_ context.Context, _ auth.Principal, surface model.Surface) (model.Observation, error) {
						observeCalls++
						return model.Observation{Surface: surface}, nil
					},
				})
			})
			s, err := server.New(server.WithNewHandler(handler))
			if err != nil {
				t.Fatal(err)
			}
			client := s.AsClient(ctx)
			if _, err = client.Initialize(ctx); err != nil {
				t.Fatal(err)
			}
			result, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_observe", Arguments: map[string]any{"sessionId": "session", "grantId": "grant", "purpose": "inspect", "surface": map[string]any{"kind": tc.surface.Kind, "bundleId": tc.surface.BundleID, "origin": tc.surface.Origin}}})
			if err != nil {
				t.Fatal(err)
			}
			if tc.allow {
				if result.IsError != nil && *result.IsError {
					t.Fatalf("allowed observation rejected: %+v", result.StructuredContent)
				}
				if observeCalls != 1 {
					t.Fatalf("Observe called %d times, want 1", observeCalls)
				}
			} else {
				if result.IsError == nil || !*result.IsError {
					t.Fatal("out-of-scope observation was not rejected")
				}
				if observeCalls != 0 {
					t.Fatalf("denied observation called Observe %d times", observeCalls)
				}
			}
		})
	}
}
