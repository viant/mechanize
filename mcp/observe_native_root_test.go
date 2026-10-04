package mcp

import (
	"context"
	"errors"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	server "github.com/viant/mcp/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"testing"
)

func TestObserveNativeRootExplicitRoutingAndConsent(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "observer", []string{"desktop:observe"})
	for _, mode := range []string{"menuBar", "focusedElement", "ordinary", "unexpectedScoped", "unexpectedWindow", "unexpectedRoots", "missingCallback", "unsupportedHelper", "unknown", "web", "denied", "unauthenticated", "wrongRoot", "wrongSurface"} {
		t.Run(mode, func(t *testing.T) {
			ctx := auth.WithPrincipal(context.Background(), p)
			if mode == "unauthenticated" {
				ctx = context.Background()
			}
			root := mode
			if mode == "ordinary" || mode == "unexpectedScoped" || mode == "unexpectedWindow" || mode == "unexpectedRoots" {
				root = ""
			}
			if mode == "missingCallback" || mode == "unsupportedHelper" || mode == "web" || mode == "denied" || (mode == "unauthenticated" || mode == "wrongRoot" || mode == "wrongSurface") {
				root = "menuBar"
			}
			kind := "native"
			if mode == "web" {
				kind = "web"
			}
			ordinary, scoped := 0, 0
			d := Dependencies{Policy: func(context.Context, auth.Principal) (script.Policy, error) {
				return script.Policy{AllowAllNative: mode != "denied", AllowAllWeb: true}, nil
			}, Observe: func(context.Context, auth.Principal, model.Surface) (model.Observation, error) {
				ordinary++
				if mode == "unexpectedWindow" {
					return model.Observation{WindowScope: map[string]string{"title": "Save"}}, nil
				}
				if mode == "unexpectedRoots" {
					return model.Observation{WindowRootsOnly: true}, nil
				}
				if mode == "unexpectedScoped" {
					return model.Observation{NativeRoot: "focusedElement"}, nil
				}
				return model.Observation{}, nil
			}, ObserveNativeRoot: func(c context.Context, a auth.Principal, s model.Surface, r string) (model.Observation, error) {
				scoped++
				binding, ok := auth.ConsentBindingFromContext(c)
				if !ok || binding != (auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "inspect"}) || a.Namespace != p.Namespace || r != root || s.BundleID != "fixture.app" {
					t.Fatal("trusted arguments lost")
				}
				if mode == "unsupportedHelper" {
					return model.Observation{}, errors.New("unsupported")
				}
				if mode == "wrongRoot" {
					r = "focusedElement"
				}
				if mode == "wrongSurface" {
					s.BundleID = "foreign.app"
				}
				return model.Observation{Surface: s, NativeRoot: r}, nil
			}}
			if mode == "missingCallback" {
				d.ObserveNativeRoot = nil
			}
			handler := protocol.WithDefaultHandler(ctx, func(b *protocol.DefaultHandler) error { return registerObserve(b, d) })
			srv, e := server.New(server.WithNewHandler(handler))
			if e != nil {
				t.Fatal(e)
			}
			client := srv.AsClient(ctx)
			if _, e = client.Initialize(ctx); e != nil {
				t.Fatal(e)
			}
			out, e := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_observe", Arguments: map[string]any{"surface": map[string]any{"kind": kind, "bundleId": "fixture.app", "origin": "https://example.com"}, "nativeRoot": root, "sessionId": "session", "grantId": "grant", "purpose": "inspect"}})
			if e != nil {
				t.Fatal(e)
			}
			success := mode == "menuBar" || mode == "focusedElement" || mode == "ordinary"
			if success == (out.IsError != nil && *out.IsError) {
				t.Fatalf("unexpected result: %+v", out)
			}
			if mode == "ordinary" || mode == "unexpectedScoped" || mode == "unexpectedWindow" || mode == "unexpectedRoots" {
				if ordinary != 1 || scoped != 0 {
					t.Fatal("legacy route changed")
				}
			} else if ordinary != 0 {
				t.Fatal("scoped request broadened to whole app")
			}
			expected := 0
			if mode == "menuBar" || mode == "focusedElement" || (mode == "unsupportedHelper" || mode == "wrongRoot" || mode == "wrongSurface") {
				expected = 1
			}
			if scoped != expected {
				t.Fatalf("scoped calls=%d want%d", scoped, expected)
			}
		})
	}
}
