package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"sync/atomic"
	"testing"
)

func TestConfirmedNonReadyInspectionRetiresZeroChildPreparation(t *testing.T) {
	for _, kind := range []string{"noFields", "pending", "busy", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			credentialHostFixtureFlow(t, "unavailable", credentialHostFixtureHooks{configure: func(f *credentialBrowserFixture) {
				f.inspectionFailure = "noCredentialFields"
				f.inspectionNoInput = kind != "pending"
				f.preflightIdle = kind != "busy"
			}, beforeStatus: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
				before := reads.Load()
				if kind == "revoked" {
					h.credentials.browserFixture = &revokeNonReadyFixture{credentialBrowserFixture: f, ctx: ctx, p: p}
				}
				out, e := h.CredentialStatus(ctx, p, ref)
				if e != nil || out.State != "needsNativeAction" || out.AttentionCode != "privateInspectionNoCredentialFields" {
					t.Fatal("non-ready diagnosis changed", out, e)
				}
				var prep data.CredentialPreparationRecord
				var children []data.CredentialDeliveryRecord
				e = h.durable.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
					var e error
					prep, children, e = h.durable.LoadCredentialRecovery(held, p, ref.PreparationID)
					return e
				})
				if e != nil {
					t.Fatal(e)
				}
				if len(children) != 0 || f.fills != 0 || f.submits != 0 || reads.Load() != before {
					t.Fatal("non-ready cleanup read secrets or created input history")
				}
				if kind == "revoked" {
					bound := auth.WithConsentBinding(ctx, f.session.consent)
					if lease, err := h.authorizeConsentOperation(bound, p, input.Surface, true, consent.Control); err == nil {
						lease.Release()
						t.Fatal("revocation did not persist")
					}
				}
				if kind == "noFields" {
					if out.PreflightRelease != "released" || prep.ProtectionState != "closed" || f.preflightRetirements != 1 {
						t.Fatal("known zero-input preflight retained admission", out.PreflightRelease, prep.ProtectionState)
					}
					release, e := h.vaultExposure.AcquireNativeExposureContext(ctx)
					if e != nil {
						t.Fatal("native observation stayed blocked", e)
					}
					release()
				} else if prep.ProtectionState != "held" || f.preflightRetirements != 0 || kind != "pending" && out.PreflightRelease != "unconfirmed" {
					t.Fatal("unproved/revoked admission was retired", kind, out.PreflightRelease)
				}
			}})
		})
	}
}

type revokeNonReadyFixture struct {
	*credentialBrowserFixture
	ctx context.Context
	p   auth.Principal
}

func (f *revokeNonReadyFixture) AdmitCredentialControl(ctx context.Context, p auth.Principal, s model.Surface, admit func(context.Context) error) (chrome.ControlAdmission, error) {
	out, e := f.credentialBrowserFixture.AdmitCredentialControl(ctx, p, s, admit)
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	request, _ := json.Marshal(map[string]any{"grantID": f.session.consent.GrantID})
	if _, err = f.host.consent.NativeRPC(human, "revoke", request); err != nil && !errors.Is(err, context.Canceled) {
		f.t.Fatal(err)
	}
	return out, e
}
