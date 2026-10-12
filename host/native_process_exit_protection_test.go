package host

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

func TestHostProcessExitReadDuringProtectionRetainsRealConsent(t *testing.T) {
	p, err := auth.NewPrincipal("fixture", "", "exit-owner", []string{"desktop:observe", "desktop:control", "consent:admin"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID, p.ClientName = "exit-client", "Exit fixture"
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "session", Purpose: "verify original exit"})
	_, file, _, _ := runtime.Caller(0)
	scoped, _ := data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	server, err := datahost.Open(scoped, filepath.Dir(filepath.Dir(file)), t.TempDir(), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	surface := model.Surface{Kind: "native", BundleID: "com.google.Chrome", ProcessID: 42, ProcessStartToken: "123:456"}
	fixture := &quitReconcileReader{target: surface, exited: true}
	reader, err := native.NewReadOnlyCaller(fixture, func(context.Context) (native.Caller, error) { t.Fatal("unexpected restart"); return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := native.NewGateway(reader, native.GatewayOptions{AllowedBundles: []string{surface.BundleID}})
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	gate, _ := vault.NewGuardedExposureGate(func(context.Context) error { return vault.ErrEntryProtected })
	h := &Host{users: map[string]User{p.Namespace: {Subject: p.Subject, DesktopAccess: true}}, native: gateway, vaultExposure: gate}
	h.consent, err = NewConsentBroker(ConsentBrokerOptions{Invoke: func(c context.Context, _ auth.Principal, r exec.ComponentRequest) (any, error) {
		return server.InvokeComponent(c, r)
	}, Enrolled: h.enrolled, SessionOwned: func(_ context.Context, actor auth.Principal, id string) error {
		if actor.Namespace != p.Namespace || id != "session" {
			return auth.ErrUnauthorized
		}
		return nil
	}, Policy: h.ConsentPolicy})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = h.readNativeProcessExit(ctx, p, surface); err == nil || fixture.reads != 0 {
		t.Fatal("exit read bypassed consent")
	}
	request, err := h.consent.Request(ctx, p, "session", consent.RequestInput{Scope: consent.Scope{Kind: "application", BundleID: surface.BundleID}, Modes: []consent.Mode{consent.Observe}, Purpose: "verify original exit", DurationSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowUntilRevoked})
	if _, err = h.consent.NativeRPC(human, "decide", decision); err != nil {
		t.Fatal(err)
	}
	if _, err = h.AuthorizeOperation(ctx, p, surface, false, consent.Observe); !errors.Is(err, vault.ErrEntryProtected) {
		t.Fatal("ordinary observation lost protection", err)
	}
	exited, proof, err := h.readNativeProcessExit(ctx, p, surface)
	if err != nil || !exited || proof.HelperEpoch == "" || fixture.reads != 1 {
		t.Fatal("closed exit evidence unavailable", err)
	}
	foreign := p
	foreign.ClientID = "foreign"
	if _, _, err = h.readNativeProcessExit(auth.WithPrincipal(ctx, foreign), foreign, surface); err == nil || fixture.reads != 1 {
		t.Fatal("foreign client borrowed consent")
	}
}
