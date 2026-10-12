package host

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

// Reproduce a broker restart with only durable original-source metadata left.
// A successor's own current consent must never become the original identity.
func TestRetrospectiveExactSourcesPreserveOriginalBarrier(t *testing.T) {
	for _, mode := range []string{"known", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			credentialHostFixtureFlow(t, mode, credentialHostFixtureHooks{clientID: "controller:" + strings.Repeat("a", 64), successorClientID: "controller:" + strings.Repeat("f", 64), exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
				_, err := h.CredentialApply(ctx, p, ref)
				if err != nil && mode != "unknown" {
					t.Fatal(err)
				}
				_, before := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
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
				f.scopeAbsent = func(c context.Context, s chrome.CredentialProtectionScope) error {
					checks++
					actor, e := auth.FromContext(c)
					if e != nil || actor.ClientID == p.ClientID || s.PreparationID != ref.PreparationID || s.Origin != input.Surface.Origin {
						t.Fatal("cleanup impersonated original identity or changed source")
					}
					return nil
				}
				result, _, _ := prepareForeignLifecycleFixture(t, h, p, input, "controller:"+strings.Repeat("f", 64))
				if result.State != "needsNativeAction" || result.AttentionCode != "scopeOtherLoginHeld" {
					t.Fatal("exact source barrier was weakened", result.AttentionCode)
				}
				prep, after := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				if prep.ProtectionState != "held" || len(after) != len(before) || checks != 0 {
					t.Fatal("retrospective cleanup failed original protection transition")
				}
				for i, row := range after {
					old := before[i]
					immutable := row
					immutable.ProtectionState, immutable.Revision, immutable.UpdatedAt = old.ProtectionState, old.Revision, old.UpdatedAt
					if immutable != old {
						t.Fatal("retrospective cleanup rewrote original input knowledge")
					}
					if row.DispatchState == "unknown" && row.ProtectionState != "held" {
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

func TestRetrospectiveAbandonedControllerPreflightRetiresOnlyZeroChildren(t *testing.T) {
	for _, kind := range []string{"absent", "busy", "liveItem", "lateProofFailure"} {
		t.Run(kind, func(t *testing.T) {
			credentialHostFixtureFlow(t, "unavailable", credentialHostFixtureHooks{clientID: "controller:" + strings.Repeat("a", 64), successorClientID: "controller:" + strings.Repeat("f", 64), exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
				original := f.session
				if original.preparation == nil || original.protected != nil || len(original.attempts) != 0 || original.protectionScope.PreparationID != "" {
					t.Fatal("fixture lacks actual failed unfilled preflight")
				}
				before, _ := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				original.cancel()
				original.selection.Revoke()
				if kind != "liveItem" {
					h.credentials.mu.Lock()
					delete(h.credentials.pending, original.id)
					h.credentials.mu.Unlock()
				}
				replacement, e := vault.NewGuardedExposureGate(func(context.Context) error { return nil })
				if e != nil {
					t.Fatal(e)
				}
				h.vaultExposure = replacement
				f.preflightIdle = kind != "busy"
				h.credentials.browserFixture = &retrospectivePreflightFixture{credentialBrowserFixture: f, t: t, owner: p.ClientID, host: h, failLate: kind == "lateProofFailure"}

				result, _, _ := prepareForeignLifecycleFixture(t, h, p, input, "controller:"+strings.Repeat("f", 64))
				prep, attempts := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				if kind == "absent" {
					if result.State != "awaitingPreflight" || prep.ProtectionState != "closed" || prep.Revision != before.Revision+1 || len(attempts) != 0 || f.preflightRetirements != 1 {
						t.Fatal("absent old controller preflight did not retire", result.AttentionCode)
					}
					unchanged := prep
					unchanged.ProtectionState, unchanged.Revision = before.ProtectionState, before.Revision
					if unchanged != before {
						t.Fatal("cleanup changed original preparation identity")
					}
				} else {
					if result.State != "needsNativeAction" || prep != before || len(attempts) != 0 || f.preflightRetirements != 0 {
						t.Fatal("unproved preflight lost barrier", kind, result.AttentionCode)
					}
				}
				if f.fills != 0 || f.submits != 0 || f.admissions != 1 {
					t.Fatal("retrospective cleanup performed input or repeated admission")
				}
			}})
		})
	}
}

type retrospectivePreflightFixture struct {
	*credentialBrowserFixture
	t                 *testing.T
	owner             string
	checks            int
	host              *Host
	failLate, checked bool
	human             auth.Principal
}

func (f *retrospectivePreflightFixture) VerifyCredentialPreflightIdle(ctx context.Context, p auth.Principal, id, origin string) error {
	f.checks++
	actual, e := auth.FromContext(ctx)
	if e != nil || actual.ClientID != p.ClientID || actual.ClientID == f.owner {
		f.t.Fatal("retrospective proof forged original actor")
	}

	if f.checks > 1 && !f.checked {
		f.checked = true
		binding, _ := auth.ConsentBindingFromContext(ctx)
		ref := gateway.CredentialRefInput{SessionID: binding.SessionID, PreparationID: id}
		for _, call := range []func(context.Context, auth.Principal, gateway.CredentialRefInput) (gateway.CredentialResult, error){f.host.CredentialApply, f.host.CredentialSubmit} {
			if _, e := call(ctx, p, ref); e == nil {
				f.t.Fatal("lifecycle seal admitted original private input")
			}
		}

		if lease, e := f.host.AuthorizeOperation(ctx, p, model.Surface{Kind: "web", Origin: origin}, true, consent.Control); e == nil {
			lease.Release()
			f.t.Fatal("preflight read seal admitted protected DOM exposure")
		}
	}
	if f.failLate && f.checks > 2 {
		return errPrivateCredential
	}
	return f.credentialBrowserFixture.VerifyCredentialPreflightIdle(ctx, p, id, origin)
}
func (f *retrospectivePreflightFixture) RetireCredentialPreflight(ctx context.Context, p auth.Principal, id, origin string) error {
	return f.credentialBrowserFixture.RetireCredentialPreflight(ctx, p, id, origin)
}
