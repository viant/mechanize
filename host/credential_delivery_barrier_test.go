package host

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

func TestCredentialBarrierFailurePrecedesOrdinaryWebExposureModes(t *testing.T) {
	for _, mode := range []consent.Mode{consent.Observe, consent.Control, consent.Record} {
		t.Run(string(mode), func(t *testing.T) {
			probes := 0
			gate, err := vault.NewGuardedExposureGate(func(context.Context) error { probes++; return nil })
			if err != nil {
				t.Fatal(err)
			}
			// A missing authenticated durable reader must refuse before any native
			// exposure probe or consent/input path, even if the volatile gate is empty.
			h := &Host{durable: &durable.Builder{}, vaultExposure: gate}
			lease, err := h.AuthorizeOperation(context.Background(), auth.Principal{}, model.Surface{Kind: "web", Origin: "https://fixture.invalid"}, mode != consent.Observe, mode)
			var diagnostic *model.MechanizeError
			if lease != nil || !errors.As(err, &diagnostic) || diagnostic.Code != "protectionMetadataUnavailable" || diagnostic.Stage != "admission" || diagnostic.DispatchState != "notDispatched" || diagnostic.EffectState != "none" {
				t.Fatal("unavailable durable protection was bypassed")
			}
			if probes != 0 {
				t.Fatal("exposure preceded durable protection check")
			}
		})
	}
}

func TestPrivateCredentialConsentCannotReplaceExposureCapabilityWithIntent(t *testing.T) {
	p, err := auth.NewPrincipal("fixture", "", "private-owner", []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID = "private-agent"
	ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), auth.ConsentBinding{GrantID: "claimed-grant", SessionID: "session", Purpose: "private fill"})
	h := &Host{chrome: &chrome.Gateway{}, durable: &durable.Builder{}}
	b := vault.Binding{SessionID: "session", DocumentID: "document", NavigationID: "navigation", Target: vault.Target{Origin: "https://fixture.example.test", Account: "alias"}}
	lease, err := h.authorizeCredentialDelivery(ctx, p, model.Surface{Kind: "web", Origin: b.Target.Origin}, b, nil)
	if lease != nil || err != vault.ErrUnavailable {
		t.Fatal("caller intent substituted for private exposure capability")
	}
	foreign := p
	foreign.ClientID = "other-agent"
	lease, err = h.authorizeCredentialDelivery(ctx, foreign, model.Surface{Kind: "web", Origin: b.Target.Origin}, b, nil)
	if lease != nil || !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("requested actor replaced original context actor")
	}
}
