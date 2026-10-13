package host

import (
	"context"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/vault"
)

func TestExtinctControllerExactSourcesRetireWithoutChangingReceipts(t *testing.T) {
	for _, mode := range []string{"known", "unknown", "partial_known", "partial_unknown"} {
		t.Run(mode, func(t *testing.T) {
			fixtureMode := strings.TrimPrefix(mode, "partial_")
			credentialHostFixtureFlow(t, fixtureMode, credentialHostFixtureHooks{clientID: "controller:" + strings.Repeat("a", 64), successorClientID: "controller:" + strings.Repeat("f", 64), exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
				_, err := h.CredentialApply(ctx, p, ref)
				if err != nil && fixtureMode != "unknown" {
					t.Fatal(err)
				}
				if fixtureMode == "known" {
					if _, err := h.CredentialSubmit(ctx, p, ref); err != nil {
						t.Fatal(err)
					}
				}
				beforePrep, before := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				original := f.session
				original.cancel()
				original.selection.Revoke()
				h.credentials.mu.Lock()
				delete(h.credentials.pending, original.id)
				h.credentials.mu.Unlock()
				// A restarted process restores the durable privacy projection, not an old
				// volatile delivery or a signed original-controller authority.
				h.vaultExposure, err = vault.NewGuardedExposureGate(func(context.Context) error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				fills, submits, admissions := f.fills, f.submits, f.admissions
				checks := 0
				partial := strings.HasPrefix(mode, "partial_")
				f.scopeAbsent = func(c context.Context, s chrome.CredentialProtectionScope) error {
					checks++
					actor, e := auth.FromContext(c)
					if e != nil || actor.ClientID == p.ClientID || s.PreparationID != ref.PreparationID || s.Origin != input.Surface.Origin {
						t.Fatal("cleanup impersonated original identity or changed source")
					}
					return nil
				}
				backend := &extinctCredentialControllerFixture{credentialBrowserFixture: f, ownerPresent: partial}
				h.credentials.browserFixture = backend
				result, successor, successorSession := prepareForeignLifecycleFixture(t, h, p, input, "controller:"+strings.Repeat("f", 64))
				if partial {
					if result.State != "needsNativeAction" {
						t.Fatal("active owner should inhibit initial preparation")
					}
					backend.ownerPresent = false
					commitFirstExtinctRetirementChild(t, h, successor, successorSession, input.Purpose, beforePrep, before)
					prep, rows := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
					if prep.ProtectionState != "held" || len(rows) != len(before) || rows[0].ProtectionState == "held" {
						t.Fatal("partial CAS did not preserve parent barrier and first receipt")
					}
					// No volatile cleanup token survives. Re-read the original durable
					// snapshot and finish remaining CAS transitions under a fresh request.
					h.credentials.mu.Lock()
					h.credentials.pending = map[string]*credentialSession{}
					h.credentials.mu.Unlock()
					result, _, _ = prepareForeignLifecycleFixture(t, h, p, input, "controller:"+strings.Repeat("f", 64))
				}

				if result.State != "awaitingPreflight" {
					t.Fatal("proven absent extinct controller source remained blocked", result.AttentionCode)
				}
				prep, after := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				if prep.ProtectionState != "closed" || len(after) != len(before) || checks == 0 {
					t.Fatal("retrospective cleanup failed original protection transition")
				}
				for i, row := range after {
					old := before[i]
					immutable := row
					immutable.ProtectionState, immutable.Revision, immutable.UpdatedAt = old.ProtectionState, old.Revision, old.UpdatedAt
					if immutable != old {
						t.Fatal("retrospective cleanup rewrote original input knowledge")
					}
					if row.DispatchState == "unknown" && row.ProtectionState != "retired" {
						t.Fatal("retrospective cleanup resolved UNKNOWN")
					}
				}
				if f.fills != fills || f.submits != submits || f.admissions != admissions {
					t.Fatal("retrospective cleanup repeated input or preflight")
				}
			}})
		})
	}
}

func TestExtinctControllerSourceRetirementRefusesUnprovedLifecycle(t *testing.T) {
	for _, kind := range []string{"liveItem", "liveController", "sourcePresent", "canceledProof", "lateProofFailure"} {
		t.Run(kind, func(t *testing.T) {
			credentialHostFixtureFlow(t, "known", credentialHostFixtureHooks{clientID: "controller:" + strings.Repeat("a", 64), successorClientID: "controller:" + strings.Repeat("f", 64), exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
				if _, err := h.CredentialApply(ctx, p, ref); err != nil {
					t.Fatal(err)
				}
				beforePrep, before := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				original := f.session
				original.cancel()
				original.selection.Revoke()
				if kind != "liveItem" {
					h.credentials.mu.Lock()
					delete(h.credentials.pending, original.id)
					h.credentials.mu.Unlock()
				}
				var err error
				h.vaultExposure, err = vault.NewGuardedExposureGate(func(context.Context) error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				fills, submits, admissions, vaultReads := f.fills, f.submits, f.admissions, reads.Load()
				checks := 0
				f.scopeAbsent = func(c context.Context, s chrome.CredentialProtectionScope) error {
					checks++
					if kind == "sourcePresent" || kind == "canceledProof" || kind == "lateProofFailure" && checks > 2 {
						return errPrivateCredential
					}
					return c.Err()
				}
				h.credentials.browserFixture = &extinctCredentialControllerFixture{credentialBrowserFixture: f, ownerPresent: kind == "liveController"}
				result, _, _ := prepareForeignLifecycleFixture(t, h, p, input, "controller:"+strings.Repeat("f", 64))
				prep, after := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				if result.State != "needsNativeAction" || prep != beforePrep || !reflect.DeepEqual(after, before) {
					t.Fatal("unproved lifecycle changed original ledger", kind, result.AttentionCode)
				}
				if f.fills != fills || f.submits != submits || f.admissions != admissions || reads.Load() != vaultReads {
					t.Fatal("refused recovery performed input/Vault read")
				}
			}})
		})
	}
}

type extinctCredentialControllerFixture struct {
	*credentialBrowserFixture
	ownerPresent bool
}

func (f *extinctCredentialControllerFixture) VerifyControllerOwnerAbsent(ctx context.Context, p auth.Principal, old string) error {
	if f.ownerPresent {
		return errOtherCredentialScopeHeld
	}
	return ctx.Err()
}

func commitFirstExtinctRetirementChild(t *testing.T, h *Host, p auth.Principal, session, purpose string, prep data.CredentialPreparationRecord, rows []data.CredentialDeliveryRecord) {
	t.Helper()
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session, Purpose: purpose})
	lease, err := h.authorizeConsentOperation(consent.RequireReusableGrant(ctx), p, model.Surface{Kind: "web", Origin: prep.Origin}, true, consent.Control)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	err = h.durable.WithCredentialDeliveryComponents(lease.Context, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
		scopes, e := h.durable.CredentialProtectionScopes(held, p)
		if e != nil || len(scopes) != 1 {
			return errPrivateCredential
		}
		valid := true
		guard := func(c context.Context) error {
			if !valid {
				return errPrivateCredential
			}
			return c.Err()
		}
		sealed, revoke, e := data.WithCredentialSourceLifecycleAuthority(held, scopes[0].Scope, guard)
		if e != nil {
			return e
		}
		defer revoke()
		clean, stop, e := data.WithCredentialSourceAbsenceAuthority(sealed, prep, rows, []data.CredentialProtectionScopeRecord{scopes[0].Scope}, guard)
		if e != nil {
			return e
		}
		defer stop()
		next := rows[0]
		next.ProtectionState = "closed"
		if next.DispatchState == "unknown" {
			next.ProtectionState = "retired"
		}
		next.Revision++
		next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		bound, release, e := data.WithCredentialDeliveryAuthority(clean, data.CredentialDeliveryAuthority{Before: &rows[0], Record: next}, guard)
		if e != nil {
			return e
		}
		defer release()
		if e = h.durable.FinishCredentialDelivery(bound, p); e != nil {
			return e
		}
		// Lose qualification after one confirmed real child CAS. A parent transition
		// must fail, leaving the original held row available for restart recovery.
		valid = false
		closed := prep
		closed.ProtectionState = "closed"
		closed.Revision++
		if _, _, e = data.WithCredentialPreparationAuthority(clean, closed, guard); e == nil {
			t.Fatal("lost proof allowed parent closure")
		}
		return nil
	})
	if err != nil {
		t.Fatal("partial child retirement fixture", err)
	}
}
