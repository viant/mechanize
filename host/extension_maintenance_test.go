package host

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	automation "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

func maintenanceHostFixture(t *testing.T) (*Host, context.Context, auth.Principal, gateway.ExtensionMaintenanceInput) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "native-maintenance", []string{"desktop:control"})
	p.ClientID = "development-agent"
	ctx := auth.WithPrincipal(context.Background(), p)
	rt, e := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("maintenance dispatched native UI input")
		return automation.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	opened, e := rt.Open(ctx, "maintenance fixture")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { rt.Close(ctx, opened.SessionID) })
	// An actual unconfigured gateway gives a finite channel refusal. Paired
	// backend/socket tests exercise the real configured channel and JS reload.
	h := &Host{Runtime: rt, chrome: &chrome.Gateway{}, users: map[string]User{p.Namespace: {DesktopAccess: true}}, vaultExposure: &vault.ExposureGate{}}
	return h, ctx, p, gateway.ExtensionMaintenanceInput{SessionID: opened.SessionID, ClientRequestID: "original-request", ExpectedVersion: "0.1.70"}
}
func TestExtensionMaintenanceHostNeedsNoNativeHelperOrAXPermission(t *testing.T) {
	h, ctx, p, in := maintenanceHostFixture(t)
	if h.nativeControl != nil || h.consent != nil {
		t.Fatal("fixture acquired native UI capabilities")
	}
	out, e := h.ExtensionReload(ctx, p, in)
	if e != nil || out.Reason != "channelUnavailable" || out.DispatchState != "notDispatched" {
		t.Fatal("protocol maintenance blocked by native UI permission", out, e)
	}
	status, e := h.ExtensionReloadStatus(ctx, p, in)
	if e != nil || status.Reason != "channelUnavailable" || status.DispatchState != "unknown" {
		t.Fatal(status, e)
	}
	release, e := h.vaultExposure.AcquireNativeExposureContext(ctx)
	if e != nil {
		t.Fatal("maintenance leaked secure-entry reservation", e)
	}
	release()
}
func TestExtensionMaintenanceHostSecureEntryForeignSessionAndControllerDenied(t *testing.T) {
	for _, mode := range []string{"secureEntry", "controller", "foreignClient", "foreignSession", "cancelled", "invalidVersion"} {
		t.Run(mode, func(t *testing.T) {
			h, ctx, p, in := maintenanceHostFixture(t)
			switch mode {
			case "secureEntry":
				admin := p
				admin.Scopes = append(admin.Scopes, "consent:admin")
				human, e := auth.WithNativeHuman(auth.WithPrincipal(ctx, admin))
				if e != nil {
					t.Fatal(e)
				}
				lease, e := h.vaultExposure.Begin(human, vault.Target{Origin: "https://fixture.test", Account: "fixture"}, func(context.Context) error { return nil })
				if e != nil {
					t.Fatal(e)
				}
				defer lease.Close(human)
			case "controller":
				p.ClientID = "controller:site"
				ctx = auth.WithPrincipal(ctx, p)
			case "foreignClient":
				p.ClientID = "foreign"
			case "foreignSession":
				in.SessionID = "foreign-session"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "invalidVersion":
				in.ExpectedVersion = "PRIVATE_CANARY"
			}
			_, e := h.ExtensionReload(ctx, p, in)
			if e == nil {
				t.Fatal("invalid maintenance request reached backend")
			}
			if mode == "secureEntry" && !errors.Is(e, vault.ErrEntryProtected) {
				t.Fatal("secure entry guard lost", e)
			}
		})
	}
}
