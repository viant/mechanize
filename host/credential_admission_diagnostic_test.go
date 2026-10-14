package host

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCredentialAdmissionDiagnosticsNameExistingRejectingBranch(t *testing.T) {
	for _, mode := range []string{"lifetime", "actor", "binding", "session", "exposure", "lease", "consent", "consentDeadline", "exposureChanged"} {
		t.Run(mode, func(t *testing.T) {
			credentialHostFixtureFlow(t, "known", credentialHostFixtureHooks{clientID: "controller:" + strings.Repeat("a", 64), exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
				item := f.session
				bound := auth.WithConsentBinding(ctx, item.consent)
				callback := h.credentials.proofAdmission(item)
				if e := callback(bound); e != nil {
					t.Fatal("original synthetic callback unavailable", e)
				}
				expected := "credentialLifetime"
				switch mode {
				case "lifetime":
					item.cancel()
				case "actor":
					different := p
					different.ClientID = "other-fixture"
					bound = auth.WithPrincipal(bound, different)
					expected = "credentialActor"
				case "binding":
					binding := item.consent
					binding.Purpose = "different fixture purpose"
					bound = auth.WithConsentBinding(bound, binding)
					expected = "credentialBinding"
				case "session":
					original := h.Runtime
					replacement, e := integration.NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
						t.Fatal("diagnostic posted input")
						return integration.StepResult{}, nil
					}, integration.Options{})
					if e != nil {
						t.Fatal(e)
					}
					h.Runtime = replacement
					defer func() { _ = replacement.Shutdown(context.Background()); h.Runtime = original }()
					expected = "credentialSession"
				case "exposure":
					item.exposure.Store(nil)
					expected = "credentialExposure"
				case "lease":
					item.protected.Retire()
					expected = "credentialLease"
				case "consent", "consentDeadline":
					h.consent.options.ControllerPolicy = func(context.Context, auth.Principal) (context.Context, time.Time, func(), error) {
						if mode == "consentDeadline" {
							return nil, time.Time{}, nil, context.DeadlineExceeded
						}
						return nil, time.Time{}, nil, errors.New("PRIVATE_CANARY")
					}
					expected = "credentialConsent"
				case "exposureChanged":
					original := h.consent.options.ControllerPolicy
					h.consent.options.ControllerPolicy = func(c context.Context, a auth.Principal) (context.Context, time.Time, func(), error) {
						out, expires, release, e := original(c, a)
						changed := *item.exposure.Load()
						item.exposure.Store(&changed)
						return out, expires, release, e
					}
					expected = "credentialExposureChanged"
				}
				err := callback(bound)
				var detail *credentialAdmissionFailure
				if !errors.As(err, &detail) || detail.CredentialAdmissionReason() != expected || !errors.Is(err, errPrivateCredential) || strings.Contains(err.Error(), "PRIVATE_CANARY") {
					t.Fatal("existing callback branch lost or leaked", mode, err)
				}
				if mode == "consentDeadline" {
					if !errors.Is(err, context.DeadlineExceeded) || webPreparationCause(err) != "deadline" {
						t.Fatal("real consent timeout lost primary deadline")
					}
				}
				if f.fills != 0 || f.submits != 0 {
					t.Fatal("diagnostic caused input")
				}
			}})
		})
	}
}
