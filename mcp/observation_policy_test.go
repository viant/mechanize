package mcp

import (
	"context"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	server "github.com/viant/mcp/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"testing"
)

func TestObserveOptionalPolicyAndLegacyFallback(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "observer", []string{"desktop:observe"})
	for _, mode := range []string{"fallback", "optional", "denied", "policyError", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(auth.WithPrincipal(context.Background(), p))
			defer cancel()
			full, cheap, observed := 0, 0, 0
			allowed := script.Policy{AllowedSurfaces: map[string]bool{"https://fixture.test": true}}
			d := Dependencies{Policy: func(context.Context, auth.Principal) (script.Policy, error) { full++; return allowed, nil }, Observe: func(c context.Context, a auth.Principal, s model.Surface) (model.Observation, error) {
				observed++
				binding, ok := auth.ConsentBindingFromContext(c)
				if !ok || binding != (auth.ConsentBinding{GrantID: "grant", SessionID: "session", Purpose: "inspect"}) || a.Namespace != p.Namespace {
					t.Fatal("existing observation authority binding changed")
				}
				return model.Observation{Surface: s}, nil
			}}
			if mode != "fallback" {
				d.ObservationPolicy = func(context.Context, auth.Principal) (script.Policy, error) {
					cheap++
					switch mode {
					case "denied":
						return script.Policy{}, nil
					case "policyError":
						return script.Policy{}, auth.ErrUnauthorized
					case "cancelled":
						cancel()
					}
					return allowed, nil
				}
			}
			handler := protocol.WithDefaultHandler(ctx, func(base *protocol.DefaultHandler) error { return registerObserve(base, d) })
			s, err := server.New(server.WithNewHandler(handler))
			if err != nil {
				t.Fatal(err)
			}
			client := s.AsClient(ctx)
			if _, err = client.Initialize(ctx); err != nil {
				t.Fatal(err)
			}
			out, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_observe", Arguments: map[string]any{"surface": model.Surface{Kind: "web", Origin: "https://fixture.test"}, "sessionId": "session", "grantId": "grant", "purpose": "inspect"}})
			accepted := err == nil && out != nil && (out.IsError == nil || !*out.IsError)
			if mode == "fallback" || mode == "optional" {
				if !accepted || observed != 1 {
					t.Fatalf("authorized route rejected: %v %+v", err, out)
				}
			} else if accepted || observed != 0 {
				t.Fatal("denied/cancelled policy reached observer")
			}
			if mode == "fallback" {
				if full != 1 || cheap != 0 {
					t.Fatal("legacy fallback changed")
				}
			} else if full != 0 || cheap != 1 {
				t.Fatal("observation rediscovered global capabilities")
			}
		})
	}
}
