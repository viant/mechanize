package host

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data/consentgrants"
	"github.com/viant/mechanize/model"
)

type observeWindowHostCaller struct {
	snapshots int
	methods   []string
}

func (*observeWindowHostCaller) Close() error { return nil }
func (c *observeWindowHostCaller) Call(ctx context.Context, r native.Request) (native.Reply, error) {
	c.methods = append(c.methods, r.Method)
	var result any
	switch r.Method {
	case "doctor":
		result = map[string]any{"axTrusted": true, "nativeWindowScopes": []string{"exactTitle"}}
	case "apps.list":
		result = map[string]any{"complete": true, "apps": []map[string]any{{"pid": 1, "bundleID": "fixture.app", "startToken": "123:4", "launchTime": "kernel:123:4"}}}
	case "elements.snapshot":
		c.snapshots++
		var params map[string]any
		if json.Unmarshal(r.Params, &params) != nil {
			return native.Reply{}, errors.New("invalid fixture request")
		}
		scope, ok := params["windowScope"].(map[string]any)
		if !ok || scope["title"] != "Insert Sheet" || scope["role"] != "window" || params["processStartToken"] != "123:4" {
			return native.Reply{}, errors.New("exact window scope lost")
		}
		nodes := []map[string]any{{"ref": "window", "nativeRole": "AXWindow", "name": "Insert Sheet"}, {"ref": "name", "parentRef": "window", "nativeRole": "AXTextField", "name": "Name", "value": "PRIVATE_VALUE"}}
		for _, node := range nodes {
			node["nativeOwnerProcessId"] = 1
			node["nativeOwnerStartToken"] = "123:4"
			node["nativeOwnerBundleId"] = "fixture.app"
			node["nativeOwnerUid"] = 501
			node["nativeOwnerMatchesRoot"] = true
		}
		now := time.Now().UTC()
		result = map[string]any{"windowScope": scope, "complete": true, "generation": 1, "observationId": "window-observation", "startedAt": now, "returnedAt": now, "nodes": nodes}
	default:
		return native.Reply{}, errors.New("unexpected native fixture operation")
	}
	raw, _ := json.Marshal(result)
	return native.Reply{ProtocolVersion: 1, RequestID: r.RequestID, HelperEpoch: "fixture", Result: raw}, nil
}
func TestHostObserveNativeWindowUsesBoundObservationGrantAndWithholdsValues(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "window-observer", []string{"desktop:observe"})
	p.ClientID = "agent"
	p.ClientName = "Fixture agent"
	for _, mode := range []string{"allowed", "wrongMode", "wrongPurpose", "wrongSession", "wrongBundle", "notEnrolled", "missingBinding", "noPID"} {
		t.Run(mode, func(t *testing.T) {
			ctx := auth.WithPrincipal(context.Background(), p)
			if mode != "missingBinding" {
				ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "inspect dialog"})
			}
			caller := &observeWindowHostCaller{}
			gateway, err := native.NewGateway(caller, native.GatewayOptions{AllowedBundles: []string{"fixture.app"}})
			if err != nil {
				t.Fatal(err)
			}
			bundles := []string{"fixture.app"}
			if mode == "notEnrolled" {
				bundles = nil
			}
			h := &Host{users: map[string]User{p.Namespace: {NativeBundles: bundles}}, nativeByUser: map[string]*native.Gateway{p.Namespace: gateway}}
			scope := `{"kind":"application","bundleID":"fixture.app"}`
			modes := `["observe"]`
			purpose := "inspect dialog"
			session := "session"
			switch mode {
			case "wrongMode":
				modes = `["control"]`
			case "wrongPurpose":
				purpose = "different"
			case "wrongSession":
				session = "different"
			case "wrongBundle":
				scope = `{"kind":"application","bundleID":"foreign.app"}`
			}
			raw, _ := json.Marshal(map[string]any{"namespace": p.Namespace, "id": "request", "clientId": p.ClientID, "sessionId": session, "scopeJson": scope, "modesJson": modes, "purpose": purpose, "durationSeconds": 60, "decision": string(consent.AllowSession), "grantId": "grant", "grantState": "active", "grantExpiresAt": time.Now().Add(time.Minute).UnixMilli()})
			var row consentgrants.Record
			if err = json.Unmarshal(raw, &row); err != nil {
				t.Fatal(err)
			}
			h.consent, err = NewConsentBroker(ConsentBrokerOptions{Enrolled: h.enrolled, SessionOwned: func(_ context.Context, _ auth.Principal, id string) error {
				if id != "session" {
					return auth.ErrUnauthorized
				}
				return nil
			}, Policy: h.ConsentPolicy, Invoke: func(context.Context, auth.Principal, exec.ComponentRequest) (any, error) {
				return &consentgrants.ListGrantsOutput{Data: []*consentgrants.Record{&row}}, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			surface := model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 1, ProcessStartToken: "123:4"}
			if mode == "noPID" {
				surface.ProcessID = 0
			}
			observed, err := h.ObserveNativeWindow(ctx, p, surface, "Insert Sheet", "window")
			if mode != "allowed" {
				if err == nil || caller.snapshots != 0 {
					t.Fatal("denied scoped read reached native snapshot", err)
				}
				return
			}
			if err != nil || caller.snapshots != 1 || observed.WindowScope["title"] != "Insert Sheet" || observed.Surface != surface {
				t.Fatal("exact window consent route failed", err)
			}
			output, _ := json.Marshal(observed)
			if strings.Contains(string(output), "PRIVATE_VALUE") {
				t.Fatal("raw AX value exposed")
			}
			for _, method := range caller.methods {
				if method != "doctor" && method != "apps.list" && method != "elements.snapshot" {
					t.Fatal("read used extra AX/value/input operation", method)
				}
			}
		})
	}
}
