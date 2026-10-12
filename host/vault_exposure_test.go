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
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

// Exercise the actual generated consent authorization path, rather than a
// substitute lease: a trusted grant cannot bypass protected native entry.
func TestVaultExposureGateCoversRealConsentLeaseLifetime(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "vault-owner", []string{"desktop:control", "consent:admin"})
	p.ClientID = "signed-console-fixture"
	p.ClientName = "Signed console fixture"
	ctx := auth.WithPrincipal(context.Background(), p)
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, file, _, _ := runtime.Caller(0)
	scoped, _ := data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	server, err := datahost.Open(scoped, filepath.Dir(filepath.Dir(file)), t.TempDir(), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	secureWindow := false
	gate, _ := vault.NewGuardedExposureGate(func(context.Context) error {
		if secureWindow {
			return vault.ErrEntryProtected
		}
		return nil
	})
	h := &Host{vaultExposure: gate, users: map[string]User{p.Namespace: {Subject: p.Subject, DesktopAccess: true, RecordingAllowed: true}}}
	h.consent, err = NewConsentBroker(ConsentBrokerOptions{
		Invoke: func(c context.Context, _ auth.Principal, r exec.ComponentRequest) (any, error) {
			return server.InvokeComponent(c, r)
		},
		Enrolled: h.enrolled, SessionOwned: func(context.Context, auth.Principal, string) error { return nil }, Policy: h.ConsentPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := h.consent.Request(ctx, p, "fixture-session", consent.RequestInput{Scope: consent.Scope{Kind: "desktop"}, Modes: []consent.Mode{consent.Observe, consent.Control, consent.Record}, Purpose: "Vault exposure proof", DurationSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowSession})
	value, err := h.consent.NativeRPC(human, "decide", decision)
	if err != nil {
		t.Fatal(err)
	}
	grant := value.(*consent.Grant)
	bound := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "fixture-session", GrantID: grant.ID, Purpose: "Vault exposure proof"})
	target := vault.Target{Origin: "https://fixture.invalid", Account: "opaque-account"}
	for _, mode := range []consent.Mode{consent.Observe, consent.Control, consent.Record} {
		lease, err := h.AuthorizeOperation(bound, p, model.Surface{Kind: "native", BundleID: "com.fixture.app"}, mode != consent.Observe, mode)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = h.vaultExposure.Begin(human, target, func(context.Context) error { return nil }); !errors.Is(err, vault.ErrBusy) {
			t.Fatal("entry overlapped admitted operation", mode)
		}
		lease.Release()
		entry, err := h.vaultExposure.Begin(human, target, func(context.Context) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		for _, surface := range []model.Surface{{Kind: "native", BundleID: "com.fixture.app"}, {Kind: "web", Origin: "https://fixture.invalid"}} {
			if _, err = h.AuthorizeOperation(bound, p, surface, mode != consent.Observe, mode); !errors.Is(err, vault.ErrEntryProtected) {
				t.Fatal("trusted consent bypassed protected entry", mode)
			}
		}
		if err = entry.Close(human); err != nil {
			t.Fatal(err)
		}
	}
	// Failed admission must not pin a permit and permanently prevent entry.
	if _, err = h.AuthorizeOperation(ctx, p, model.Surface{Kind: "native", BundleID: "com.fixture.app"}, false, consent.Observe); err == nil {
		t.Fatal("unbound operation admitted")
	}
	entry, err := h.vaultExposure.Begin(human, target, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal("failed admission retained exposure permit")
	}
	if err = entry.Close(human); err != nil {
		t.Fatal(err)
	}
	// Retained browser delivery is not a global desktop prohibition, even when
	// its durable reader is unavailable. Native secure-entry protection remains.
	deliveryBinding := vault.Binding{SessionID: "fixture-session", DocumentID: "login-document", NavigationID: "navigation", Target: target}
	delivery, err := gate.BeginDelivery(bound, deliveryBinding, func(c context.Context) error { return c.Err() }, func(context.Context) error { return vault.ErrEntryCleanup })
	if err != nil {
		t.Fatal(err)
	}
	defer delivery.Retire()
	h.durable = &durable.Builder{} // Any obsolete global durable query would fail.
	for _, mode := range []consent.Mode{consent.Observe, consent.Control, consent.Record} {
		lease, e := h.AuthorizeOperation(bound, p, model.Surface{Kind: "native", BundleID: "com.fixture.app"}, mode != consent.Observe, mode)
		if e != nil {
			t.Fatal("browser delivery blocked independently approved native operation", mode, e)
		}
		if _, e = gate.AcquireExposureContext(bound); !errors.Is(e, vault.ErrDeliveryProtected) {
			t.Fatal("native operation retired browser protection")
		}
		lease.Release()
	}
	secureWindow = true
	if _, err = h.AuthorizeOperation(bound, p, model.Surface{Kind: "native", BundleID: "com.fixture.app"}, false, consent.Observe); !errors.Is(err, vault.ErrEntryProtected) {
		t.Fatal("independent secure-window protection bypassed", err)
	}
	secureWindow = false
	if _, err = h.AuthorizeOperation(ctx, p, model.Surface{Kind: "native", BundleID: "com.fixture.app"}, false, consent.Observe); err == nil {
		t.Fatal("native policy change bypassed original consent")
	}

}
