package host

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data/consentgrants"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
	"time"
)

func TestHostObserveNativeRootRequiresSameConsentAndIdentity(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "observer", []string{"desktop:observe"})
	p.ClientID = "agent"
	p.ClientName = "Fixture agent"
	ctx := auth.WithPrincipal(context.Background(), p)
	h := &Host{users: map[string]User{p.Namespace: {DesktopAccess: true}}}
	surface := model.Surface{Kind: "native", BundleID: "fixture.app"}
	for _, root := range []string{"menuBar", "focusedElement"} {
		if _, e := h.ObserveNativeRoot(ctx, p, surface, root); e == nil {
			t.Fatal("missing consent broker allowed read")
		}
	}
	calls := 0
	h.consent, _ = NewConsentBroker(ConsentBrokerOptions{Enrolled: h.enrolled, SessionOwned: func(context.Context, auth.Principal, string) error { return nil }, Policy: func(context.Context, auth.Principal, consent.Scope, []consent.Mode, int) error { return nil }, Invoke: func(context.Context, auth.Principal, exec.ComponentRequest) (any, error) {
		calls++
		t.Fatal("unbound request reached persistence")
		return nil, nil
	}})
	for _, root := range []string{"menuBar", "focusedElement"} {
		if _, e := h.ObserveNativeRoot(ctx, p, surface, root); e == nil {
			t.Fatal("missing consent binding allowed read")
		}
	}
	for _, tc := range []struct {
		root    string
		surface model.Surface
		ctx     context.Context
	}{{"unknown", surface, ctx}, {"", surface, ctx}, {"menuBar", model.Surface{Kind: "web", Origin: "https://example.com"}, ctx}, {"menuBar", surface, context.Background()}} {
		if _, e := h.ObserveNativeRoot(tc.ctx, p, tc.surface, tc.root); e == nil {
			t.Fatal("invalid scope/identity accepted")
		}
	}
	if calls != 0 {
		t.Fatal("denied read reached persistence")
	}
}

// Only the private component's returned fixture rows are mocked; the real
// consent service still checks exact client/session/scope/purpose/mode bindings.
func TestHostObserveNativeRootWithBoundConsentAndValueWithholding(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "observer", []string{"desktop:observe"})
	p.ClientID = "agent"
	p.ClientName = "Fixture agent"
	ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "inspect"})
	for _, mode := range []string{"allowed", "wrongMode", "wrongBundle", "wrongPurpose", "wrongSession", "notEnrolled"} {
		t.Run(mode, func(t *testing.T) {
			caller := &observeRootCaller{}
			gateway, e := native.NewGateway(caller, native.GatewayOptions{AllowedBundles: []string{"fixture.app"}})
			if e != nil {
				t.Fatal(e)
			}
			bundles := []string{"fixture.app"}
			if mode == "notEnrolled" {
				bundles = nil
			}
			h := &Host{users: map[string]User{p.Namespace: {NativeBundles: bundles}}, nativeByUser: map[string]*native.Gateway{p.Namespace: gateway}}
			scope := `{"kind":"application","bundleID":"fixture.app"}`
			modes := `["observe"]`
			purpose := "inspect"
			session := "session"
			switch mode {
			case "wrongMode":
				modes = `["control"]`
			case "wrongBundle":
				scope = `{"kind":"application","bundleID":"foreign.app"}`
			case "wrongPurpose":
				purpose = "other"
			case "wrongSession":
				session = "foreign"
			}
			rowBytes, _ := json.Marshal(map[string]any{"namespace": p.Namespace, "id": "request", "clientId": p.ClientID, "sessionId": session, "scopeJson": scope, "modesJson": modes, "purpose": purpose, "durationSeconds": 60, "decision": string(consent.AllowSession), "grantId": "grant", "grantState": "active", "grantExpiresAt": time.Now().Add(time.Minute).UnixMilli()})
			var row consentgrants.Record
			if e = json.Unmarshal(rowBytes, &row); e != nil {
				t.Fatal(e)
			}
			h.consent, e = NewConsentBroker(ConsentBrokerOptions{Enrolled: h.enrolled, SessionOwned: func(_ context.Context, _ auth.Principal, s string) error {
				if s != "session" {
					return auth.ErrUnauthorized
				}
				return nil
			}, Policy: h.ConsentPolicy, Invoke: func(context.Context, auth.Principal, exec.ComponentRequest) (any, error) {
				return &consentgrants.ListGrantsOutput{Data: []*consentgrants.Record{&row}}, nil
			}})
			if e != nil {
				t.Fatal(e)
			}
			obs, e := h.ObserveNativeRoot(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"}, "menuBar")
			if mode != "allowed" {
				if e == nil || caller.snapshots != 0 {
					t.Fatalf("denied read dispatched: %+v %v", obs, e)
				}
				return
			}
			if e != nil || obs.NativeRoot != "menuBar" || caller.snapshots != 1 {
				t.Fatalf("scoped read failed: %+v %v", obs, e)
			}
			body, _ := json.Marshal(obs)
			if strings.Contains(string(body), "PRIVATE_VALUE") {
				t.Fatal("values exposed")
			}
		})
	}
}

type observeRootCaller struct{ snapshots int }

func (*observeRootCaller) Close() error { return nil }
func (c *observeRootCaller) Call(ctx context.Context, r native.Request) (native.Reply, error) {
	if e := ctx.Err(); e != nil {
		return native.Reply{}, e
	}
	var out any
	switch r.Method {
	case "doctor":
		out = map[string]any{"axTrusted": true, "nativeRootScopes": []string{"menuBar"}}
	case "apps.list":
		out = map[string]any{"complete": true, "apps": []map[string]any{{"pid": 1, "bundleID": "fixture.app", "launchTime": "launch"}}}
	case "elements.snapshot":
		var p map[string]any
		if json.Unmarshal(r.Params, &p) != nil || p["rootScope"] != "menuBar" {
			return native.Reply{}, fmt.Errorf("wrong root")
		}
		c.snapshots++
		out = map[string]any{"rootScope": "menuBar", "complete": true, "generation": 1, "observationId": "obs", "nodes": []map[string]any{{"ref": "x", "name": "Go", "nativeRole": "AXMenuItem", "value": "PRIVATE_VALUE"}}}
	default:
		return native.Reply{}, fmt.Errorf("unexpected method")
	}
	raw, _ := json.Marshal(out)
	return native.Reply{HelperEpoch: "fixture", Result: raw}, nil
}
