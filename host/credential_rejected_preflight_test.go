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

func TestReleasedInspectionAllowsFreshPrepareInSameSession(t *testing.T) {
	credentialHostFixtureFlow(t, "unavailable", credentialHostFixtureHooks{configure: func(f *credentialBrowserFixture) {
		f.inspectionFailure = "noCredentialFields"
		f.inspectionNoInput = true
		f.preflightIdle = true
	}, beforeStatus: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
		original := f.session
		out, e := h.CredentialStatus(ctx, p, ref)
		if e != nil || out.PreflightRelease != "released" {
			t.Fatal("negative inspection not confirmed released", e)
		}
		prep, children := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
		if prep.ProtectionState != "closed" || len(children) != 0 {
			t.Fatal("fixture retained original input protection")
		}
		fresh, e := h.CredentialPrepare(ctx, p, input)
		if e != nil || fresh.State != "awaitingPreflight" || fresh.PreparationID == ref.PreparationID {
			t.Fatal("released item blocks identical same-session Prepare", e)
		}
		h.credentials.mu.Lock()
		f.session = h.credentials.pending[fresh.PreparationID]
		_, retained := h.credentials.pending[ref.PreparationID]
		h.credentials.mu.Unlock()
		if retained || original.done.Err() == nil {
			t.Fatal("old canceled selection remains usable")
		}
		f.inspectionFailure = ""
		f.inspectionNoInput = false
		f.unavailable = false
		f.admissionTransform = func(c context.Context, a chrome.ControlAuthority) (chrome.ControlAuthority, error) {
			a.Document.DocumentID = "fresh-document"
			a.Document.Generation++
			return a, c.Err()
		}
		ready, e := h.CredentialStatus(ctx, p, gateway.CredentialRefInput{SessionID: input.SessionID, PreparationID: fresh.PreparationID})
		if e != nil || ready.State != "ready" || f.session.binding.DocumentID != "fresh-document" {
			t.Fatal("new preparation failed fresh document qualification", ready.State, e)
		}
		after, rows := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
		if after != prep || len(rows) != 0 || f.fills != 0 || f.submits != 0 {
			t.Fatal("retry changed old history or dispatched input")
		}
		if _, e = h.CredentialApply(ctx, p, ref); e == nil {
			t.Fatal("old preparation resumed private input")
		}
	}})
}
