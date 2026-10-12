package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/engine/durable"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
	"sync/atomic"
	"testing"
)

type publicReadTestContextKey struct{}
type publicReadBrowserFixture struct {
	*credentialBrowserFixture
	deny  bool
	calls int
}

func (f *publicReadBrowserFixture) WithVerifiedCredentialPublicRead(ctx context.Context, p auth.Principal, s model.Surface) (context.Context, error) {
	f.calls++
	actual, e := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if e != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || !ok || binding.SessionID == "" || s.Kind != "web" || s.TabID != "profile/browser/7" || f.deny {
		return nil, errors.New("closed fixture refusal")
	}
	return context.WithValue(ctx, publicReadTestContextKey{}, true), nil
}

type tabReadFixture struct{ calls int }

func (f *tabReadFixture) ListTabHandles(ctx context.Context, p auth.Principal, origin string) (chrome.TabHandleInventory, error) {
	f.calls++
	return chrome.TabHandleInventory{Tabs: []chrome.TabHandle{{Handle: "profile/browser/7", Origin: origin}}, Complete: true}, ctx.Err()
}

func TestCredentialPublicReadPreservesUnknownHistoryConsentAndPrivateLease(t *testing.T) {
	credentialHostFixtureFlow(t, "publicRead", credentialHostFixtureHooks{exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, in gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
		if r, e := h.CredentialApply(ctx, p, ref); e != nil || r.State != "filled" {
			t.Fatal("fixture fill failed", e)
		}
		f.submitUnknown = true
		if _, e := h.CredentialSubmit(ctx, p, ref); e != nil {
			t.Fatal(e)
		}
		original := f.session
		bound := auth.WithConsentBinding(ctx, original.consent)
		history := func() []byte {
			var out []byte
			e := h.durable.WithCredentialDeliveryComponents(bound, p, func(c context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
				prep, rows, e := h.durable.LoadCredentialRecovery(c, p, ref.PreparationID)
				if e != nil {
					return e
				}
				unknown := false
				for _, r := range rows {
					unknown = unknown || r.DispatchState == "unknown"
				}
				if !unknown {
					t.Fatal("fixture lacks original UNKNOWN")
				}
				out, e = json.Marshal(struct {
					Prep any
					Rows any
				}{prep, rows})
				return e
			})
			if e != nil {
				t.Fatal(e)
			}
			return out
		}
		before := string(history())
		vaultReads := reads.Load()
		fills, submits := f.fills, f.submits
		reader := &publicReadBrowserFixture{credentialBrowserFixture: f}
		h.credentials.browserFixture = reader
		surface := model.Surface{Kind: "web", Origin: in.Surface.Origin, TabID: "profile/browser/7"}
		lease, e := h.AuthorizeOperation(bound, p, surface, false, consent.Observe)
		if e != nil {
			t.Fatal("same-tab public read denied", e)
		}
		if lease.Context.Value(publicReadTestContextKey{}) != true {
			t.Fatal("proof context lost")
		}
		if e = original.protected.WithDelivery(lease.Context, original.binding, func() error { t.Fatal("private input overlapped scoped read"); return nil }); e == nil {
			t.Fatal("private input admitted")
		}
		lease.Release()
		if _, e = h.vaultExposure.AcquireExposureContext(bound); !errors.Is(e, vault.ErrDeliveryProtected) {
			t.Fatal("read cleared original protection")
		}
		reader.deny = true
		if _, e = h.AuthorizeOperation(bound, p, surface, false, consent.Observe); e == nil {
			t.Fatal("login/stale proof admitted")
		}
		reader.deny = false
		calls := reader.calls
		if _, e = h.AuthorizeOperation(ctx, p, surface, false, consent.Observe); e == nil || reader.calls != calls {
			t.Fatal("missing consent reached renderer")
		}
		if _, e = h.AuthorizeOperation(bound, p, surface, true, consent.Control); e == nil || reader.calls != calls {
			t.Fatal("public read borrowed mutation authority")
		}
		tabs := &tabReadFixture{}
		result, e := h.browserTabs(bound, p, model.Surface{Kind: "web", Origin: surface.Origin}, tabs)
		if e != nil || len(result.Tabs) != 1 || tabs.calls != 1 {
			t.Fatal("protected tab metadata unavailable", e)
		}
		if _, e = h.browserTabs(ctx, p, model.Surface{Kind: "web", Origin: surface.Origin}, tabs); e == nil || tabs.calls != 1 {
			t.Fatal("tab metadata bypassed consent")
		}
		if before != string(history()) || reads.Load() != vaultReads || f.fills != fills || f.submits != submits {
			t.Fatal("read changed original history or repeated private input")
		}
	}})
}
