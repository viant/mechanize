package host

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

type failingPublicReadFixture struct {
	*credentialBrowserFixture
	failure      error
	calls        int
	panicFailure bool
	cancelProof  context.CancelFunc
}

func (f *failingPublicReadFixture) WithVerifiedCredentialPublicRead(ctx context.Context, p auth.Principal, s model.Surface) (context.Context, error) {
	f.calls++
	if f.panicFailure {
		panic("PRIVATE_CANARY verifier panic")
	}
	actual, e := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if e != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || !ok || binding.SessionID == "" || s.Kind != "web" {
		return nil, errors.New("fixture admission was not reached")
	}
	if f.cancelProof != nil {
		f.cancelProof()
		return ctx, nil
	}
	return nil, f.failure
}

// Regression contract: the private read verifier remains mandatory, but its
// transport/identity failure must not claim that a public page is a login DOM.
func TestCredentialPublicReadFailureClassification(t *testing.T) {
	credentialHostFixtureFlow(t, "publicRead", credentialHostFixtureHooks{exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, in gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
		bound := auth.WithConsentBinding(ctx, f.session.consent)
		_, stale := (&chrome.Gateway{}).WithVerifiedCredentialPublicRead(bound, p, in.Surface)
		if chrome.CredentialProtectionFailureReason(stale) != "scopeChanged" {
			t.Fatal("fixture did not obtain actual typed scope failure")
		}
		cases := []struct {
			name    string
			failure error
			code    string
			private bool
		}{
			{"actualVaultExclusion", vault.ErrDeliveryProtected, "", true},
			{"staleBinding", stale, "publicReadIdentityChanged", false},
			{"transportDeadline", context.DeadlineExceeded, "publicReadUnavailable", false},
			{"unclassifiedVerifier", errors.New("PRIVATE_CANARY internal renderer detail"), "publicReadUnavailable", false},
			{"panicVerifier", nil, "publicReadUnavailable", false},
			{"missingProof", nil, "publicReadUnavailable", false},
			{"canceledAfterProof", nil, "publicReadUnavailable", false},
		}
		beforeReads, fills, submits := reads.Load(), f.fills, f.submits
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				reader := &failingPublicReadFixture{credentialBrowserFixture: f, failure: tc.failure, panicFailure: tc.name == "panicVerifier"}
				readContext := bound
				if tc.name == "canceledAfterProof" {
					var cancel context.CancelFunc
					readContext, cancel = context.WithCancel(bound)
					reader.cancelProof = cancel
					defer cancel()
				}
				h.credentials.browserFixture = reader
				lease, handled, e := h.authorizeCredentialPublicRead(readContext, p, model.Surface{Kind: "web", Origin: in.Surface.Origin, TabID: "profile/browser/7"})
				if lease != nil || !handled || e == nil || reader.calls != 1 {
					t.Fatal("failed proof admitted a lease or changed routing")
				}
				if tc.private {
					if !errors.Is(e, vault.ErrDeliveryProtected) {
						t.Fatal("actual Vault exclusion lost")
					}
					return
				}
				if errors.Is(e, vault.ErrDeliveryProtected) {
					t.Errorf("nonprivacy %s became a protected-DOM diagnosis", tc.name)
				}
				var failure *model.MechanizeError
				if !errors.As(e, &failure) || failure.Code != tc.code || failure.Stage != "admission" || failure.DispatchState != "notDispatched" || failure.EffectState != "none" {
					t.Errorf("missing finite no-input classification: %T", e)
				}
				if strings.Contains(e.Error(), "PRIVATE_CANARY") {
					t.Fatal("raw verifier error escaped")
				}
			})
		}
		if reads.Load() != beforeReads || f.fills != fills || f.submits != submits {
			t.Fatal("classification read credentials or dispatched input")
		}
	}})
}

func TestCredentialPublicReadClosedFailureVocabulary(t *testing.T) {
	cases := map[string]string{"scopeChanged": "publicReadIdentityChanged", "scopeInventoryUnavailable": "publicReadInventoryUnavailable", "scopePreflightBusy": "publicReadBusy", "scopeLimit": "publicReadLimit", "scopeUnavailable": "publicReadUnavailable", "PRIVATE_CANARY": "publicReadUnavailable"}
	for reason, code := range cases {
		e := credentialPublicReadFailure(reason)
		var failure *model.MechanizeError
		if !errors.As(e, &failure) || failure.Code != code || failure.DispatchState != "notDispatched" || failure.EffectState != "none" || strings.Contains(e.Error(), "PRIVATE_CANARY") {
			t.Fatalf("bad closed reason %s", code)
		}
	}
	if !errors.Is(credentialPublicReadFailure("scopeTargetProtected"), vault.ErrDeliveryProtected) {
		t.Fatal("actual target protection lost")
	}
}

func TestCredentialPublicReadNativeProbeFailureIsUnavailableAndActualEntryRemainsProtected(t *testing.T) {
	credentialHostFixtureFlow(t, "publicRead", credentialHostFixtureHooks{exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, _ gateway.CredentialRefInput, in gateway.CredentialPrepareInput, f *credentialBrowserFixture, _ *atomic.Int64) {
		for _, protected := range []bool{false, true} {
			reader := &publicReadBrowserFixture{}
			h.credentials.browserFixture = reader
			gate, err := vault.NewGuardedExposureGate(func(context.Context) error {
				if protected {
					return vault.ErrEntryProtected
				}
				return errors.New("synthetic probe details")
			})
			if err != nil {
				t.Fatal(err)
			}
			h.vaultExposure = gate
			bound := auth.WithConsentBinding(ctx, f.session.consent)
			lease, handled, err := h.authorizeCredentialPublicRead(bound, p, model.Surface{Kind: "web", Origin: in.Surface.Origin, TabID: "profile/browser/7"})
			if lease != nil || !handled || err == nil || reader.calls != 0 {
				t.Fatal("native probe failure minted a renderer permit", err)
			}
			if protected {
				if !errors.Is(err, vault.ErrDeliveryProtected) {
					t.Fatal("actual native entry protection changed", err)
				}
			} else {
				var detail *model.MechanizeError
				if errors.Is(err, vault.ErrDeliveryProtected) || !errors.As(err, &detail) || detail.Code != "publicReadUnavailable" || strings.Contains(err.Error(), "synthetic probe details") {
					t.Fatal("unavailable native probe became private DOM", err)
				}
			}
		}
	}})
}
