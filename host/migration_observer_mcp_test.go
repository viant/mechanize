package host

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data/consentgrants"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestMigrationObserverMCPUsesRealHostConsentGate(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "window-observer", []string{"desktop:observe"})
	p.ClientID = "agent"
	p.ClientName = "Fixture agent"
	for _, mode := range []string{"allowed", "wrongMode", "wrongPurpose", "wrongSession", "wrongBundle", "notEnrolled", "missingBinding", "noPID", "missingPurpose", "missingSession"} {
		t.Run(mode, func(t *testing.T) {
			ctx := auth.WithPrincipal(context.Background(), p)
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
			runtime, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
				return automation.StepResult{}, errors.New("input forbidden")
			})
			if err != nil {
				t.Fatal(err)
			}
			server, err := mcp.New(mcp.Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) {
				return script.Policy{AllowedSurfaces: map[string]bool{"fixture.app": true}}, nil
			}, ObserveNativeWindow: h.ObserveNativeWindow})
			if err != nil {
				t.Fatal(err)
			}
			client := server.AsClient(ctx)
			if _, err = client.Initialize(ctx); err != nil {
				t.Fatal(err)
			}
			args := map[string]any{"surface": surface, "windowScope": map[string]any{"title": "Insert Sheet", "role": "AXWindow"}, "sessionId": "session", "purpose": "inspect dialog", "grantId": "grant"}
			if mode == "missingBinding" {
				delete(args, "sessionId")
				delete(args, "purpose")
				delete(args, "grantId")
			}
			if mode == "missingPurpose" {
				delete(args, "purpose")
			}
			if mode == "missingSession" {
				delete(args, "sessionId")
			}
			result, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_observe", Arguments: args})
			accepted := err == nil && result != nil && (result.IsError == nil || !*result.IsError)
			if mode != "allowed" {
				if accepted || caller.snapshots != 0 {
					t.Fatal("unauthorized observer reached native snapshot", err)
				}
				return
			}
			if !accepted || caller.snapshots != 1 {
				t.Fatal("reviewed observer binding did not reach real host", err, result)
			}
			raw, _ = json.Marshal(result)
			if strings.Contains(string(raw), "PRIVATE_VALUE") {
				t.Fatal("raw value escaped")
			}
		})
	}
}
