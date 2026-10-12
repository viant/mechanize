package host

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

func exerciseCredentialScopePolicy(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, mode string, reads *atomic.Int64) {
	t.Helper()
	original := f.session
	before := reads.Load()
	if mode == "scopeDisjoint" {
		checks := 0
		f.scopeDisjoint = func(_ context.Context, source chrome.CredentialProtectionScope, target model.Surface) error {
			checks++
			if source.PreparationID != ref.PreparationID || source.Identity.DocumentID != "username-document" || source.LoginRouteSHA256 == "" {
				t.Fatal("untrusted scope used")
			}
			if target.TabID == "profile/browser/8" {
				return nil
			}
			return errPrivateCredential
		}
		bound := auth.WithConsentBinding(ctx, original.consent)
		for _, origin := range []string{input.Surface.Origin, "https://unrelated.invalid"} {
			target := model.Surface{Kind: "web", Origin: origin, TabID: "profile/browser/8"}
			lease, e := h.AuthorizeOperation(bound, p, target, false, consent.Observe)
			if e != nil {
				t.Fatal("disjoint ordinary read blocked", e)
			}
			if e = original.protected.WithDelivery(lease.Context, original.binding, func() error { t.Fatal("private input while disjoint reader"); return nil }); e == nil {
				t.Fatal("scoped reader failed private-input exclusion")
			}
			lease.Release()
		}
		other := input
		other.Surface.Origin = "https://unrelated.invalid"
		blocked, e := h.CredentialPrepare(ctx, p, other)
		if e != nil || blocked.State != "needsNativeAction" || blocked.AttentionCode != "scopeOtherLoginHeld" || original.done.Err() != nil {
			t.Fatal("new private flow changed unrelated protection", blocked, e)
		}
		if checks != 2 || reads.Load() != before || f.privacyCalls != 0 || f.fills != 0 || f.submits != 0 {
			t.Fatal("unrelated observation performed Vault/redactor/input ceremony")
		}
		if _, e := h.AuthorizeOperation(bound, p, model.Surface{Kind: "web", Origin: input.Surface.Origin, TabID: "profile/browser/7"}, false, consent.Observe); e == nil {
			t.Fatal("source bypassed private DOM promotion")
		}
		if _, e := h.vaultExposure.AcquireExposure(); !errors.Is(e, vault.ErrDeliveryProtected) {
			t.Fatal("scoped observation cleared delivery gate")
		}
		return
	}
	// Known and unknown inputs keep their original dispatch knowledge through
	// automatic source cleanup. No fill or submit is repeated by Prepare.
	applied, e := h.CredentialApply(ctx, p, ref)
	if e != nil || applied.State == "needsNativeAction" {
		t.Fatal("fixture input failed", applied, e)
	}
	if mode == "scopeCleanup" {
		if result, e := h.CredentialSubmit(ctx, p, ref); e != nil || result.State == "needsNativeAction" {
			t.Fatal("known submit fixture failed", result, e)
		}
	}
	fills, submits := f.fills, f.submits
	var pinned *credentialScopePinFixture
	if mode == "scopeCleanupPinned" {
		pinned = &credentialScopePinFixture{credentialBrowser: f, t: t}
		h.credentials.browserFixture = pinned
	}
	calls := 0
	f.scopeAbsent = func(c context.Context, source chrome.CredentialProtectionScope) error {
		calls++
		if pinned != nil && c.Value(credentialScopePinFixtureKey{}) != pinned {
			t.Fatal("source proof lost opaque process pin")
		}
		if source.Identity.DocumentID != "username-document" || source.PreparationID != ref.PreparationID {
			t.Fatal("cleanup changed original source")
		}
		if mode == "scopeCleanupTimeout" {
			<-c.Done()
			return c.Err()
		}
		if mode == "scopeCleanupAbsentFail" {
			return errPrivateCredential
		}

		return nil
	}

	if strings.HasPrefix(mode, "scopeCleanupManualStaging") {
		// Reproduce the old failure using only synthetic fixture state: the broker
		// restarted, then a manual staging lease was retired without being tracked.
		// UNKNOWN here tests protection retirement only; real manual resume still
		// rejects UNKNOWN before it can start manual staging.
		original.cancel()
		if original.selection != nil {
			original.selection.Revoke()
		}
		h.credentials.mu.Lock()
		delete(h.credentials.pending, original.id)
		h.credentials.mu.Unlock()
		replacement, e := vault.NewGuardedExposureGate(func(context.Context) error { return nil })
		if e != nil {
			t.Fatal(e)
		}
		h.vaultExposure = replacement
		resumed, e := h.Runtime.Open(ctx, "manual staging restart fixture")
		if e != nil {
			t.Fatal(e)
		}
		defer h.Runtime.Close(ctx, resumed.SessionID)
		input.SessionID = resumed.SessionID
		requestCtx := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: resumed.SessionID, Purpose: "Resume redacted browser observation after manual login"})
		consentLease, e := h.authorizeConsentOperation(requestCtx, p, input.Surface, true, consent.Control)
		if e != nil {
			t.Fatal(e)
		}
		cb, ok := auth.ConsentBindingFromContext(consentLease.Context)
		consentLease.Release()
		if !ok {
			t.Fatal("manual fixture lacks current consent")
		}
		stagingCtx := auth.WithConsentBinding(ctx, cb)
		manualBinding := original.binding
		manualBinding.SessionID = resumed.SessionID
		staging, e := replacement.BeginManualDOMTransition(stagingCtx, manualBinding, func(context.Context) error { return nil })
		if e != nil {
			t.Fatal(e)
		}
		staging.Retire()
		refused, e := h.CredentialPrepare(ctx, p, input)
		if e != nil || refused.State != "needsNativeAction" || refused.AttentionCode != "scopeUnavailable" || refused.PreparationID != "" {
			t.Fatal("orphan regression not reproduced", refused, e)
		}
		if f.fills != fills || f.submits != submits {
			t.Fatal("orphan diagnostic repeated private input")
		}
		var prep data.CredentialPreparationRecord
		e = h.durable.WithCredentialDeliveryComponents(stagingCtx, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
			var e error
			prep, _, e = h.durable.LoadCredentialRecovery(held, p, ref.PreparationID)
			return e
		})
		if e != nil {
			t.Fatal(e)
		}
		retained, e := h.credentials.retainManualStaging(p, prep, cb, manualBinding, staging)
		if e != nil {
			t.Fatal(e)
		}
		if retained.protected != staging || retained.dom != nil || retained.selection != nil || retained.state != "needsNativeAction" {
			t.Fatal("tracking granted DOM or secret authority")
		}
		if mode == "scopeCleanupManualStagingAbsentFail" {
			f.scopeAbsent = func(context.Context, chrome.CredentialProtectionScope) error { return errPrivateCredential }
		}
	}
	if mode == "scopeCleanupLateFail" {
		f.scopeRetire = func(context.Context, chrome.CredentialProtectionScope) error { return errPrivateCredential }
	}
	start := time.Now()
	next, e := h.CredentialPrepare(ctx, p, input)
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Fatal("source cleanup exceeded bounded operation", elapsed)
	}
	if e != nil {
		t.Fatal("prepare did not return closed source diagnostic", e)
	}
	if f.fills != fills || f.submits != submits {
		t.Fatal("cleanup replayed private input")
	}
	if mode == "scopeCleanupAbsentFail" || mode == "scopeCleanupLateFail" || mode == "scopeCleanupTimeout" || mode == "scopeCleanupManualStagingAbsentFail" {
		if next.State != "needsNativeAction" || next.AttentionCode == "" {
			t.Fatal("incomplete source proof admitted new login", next)
		}
		if _, e = h.vaultExposure.AcquireExposure(); !errors.Is(e, vault.ErrDeliveryProtected) {
			t.Fatal("failed source proof released volatile protection", e)
		}
		if mode == "scopeCleanupAbsentFail" || mode == "scopeCleanupTimeout" || mode == "scopeCleanupManualStagingAbsentFail" {
			if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
				t.Fatal("failed initial proof changed durable protection", e)
			}
			return
		}
		// A later explicit Prepare can finish the retained volatile cleanup after
		// the independent proof becomes available, without replaying the old effect.
		f.scopeAbsent = func(context.Context, chrome.CredentialProtectionScope) error { return nil }
		f.scopeRetire = nil
		next, e = h.CredentialPrepare(ctx, p, input)
		if e != nil {
			t.Fatal(e)
		}
	}
	if next.State != "awaitingPreflight" || next.PreparationID == ref.PreparationID || next.PreparationID == "" {
		t.Fatal("proved source absence did not permit fresh preparation", next, e, calls)
	}
	bound := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: input.SessionID, Purpose: input.Purpose})
	e = h.durable.WithCredentialDeliveryComponents(bound, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
		prep, rows, e := h.durable.LoadCredentialRecovery(held, p, ref.PreparationID)
		if e != nil {
			return e
		}
		if prep.ProtectionState != "closed" || len(rows) != len(original.attempts) {
			t.Fatal("cleanup removed original ledger")
		}
		originalByID := make(map[string]data.CredentialDeliveryRecord, len(original.attempts))
		for _, row := range original.attempts {
			originalByID[row.AttemptID] = row
		}
		for _, row := range rows {
			old, exists := originalByID[row.AttemptID]
			if !exists || row.DispatchState != old.DispatchState || row.AttemptID != old.AttemptID || row.DocumentID != old.DocumentID || row.SelectedRevision != old.SelectedRevision {
				t.Fatal("cleanup changed effect knowledge")
			}
			if row.DispatchState == "unknown" && row.ProtectionState != "retired" {
				t.Fatal("unknown dispatch was resolved instead of exposure retirement")
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if pinned != nil && (pinned.starts != 1 || pinned.finishes < 2) {
		t.Fatal("process verification did not bracket retirement", pinned.starts, pinned.finishes)
	}
	t.Logf("source cleanup: %d retained attempts, %d bounded source verification calls", len(original.attempts), calls)
	if calls > 256 {
		t.Fatal("source proof calls unexpectedly multiplied", calls)
	}
	if original.done.Err() == nil {
		t.Fatal("retired source still holds live private capability")
	}
}

type credentialScopePinFixtureKey struct{}
type credentialScopePinFixture struct {
	credentialBrowser
	t                *testing.T
	starts, finishes int
}

func (f *credentialScopePinFixture) PinCredentialScopeProcesses(ctx context.Context, p auth.Principal, sources []chrome.CredentialProtectionScope) (context.Context, func(context.Context) error, error) {
	f.starts++
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || binding.GrantID == "" || len(sources) == 0 {
		f.t.Fatal("process pin lacked current consent/source")
	}
	pinned := context.WithValue(ctx, credentialScopePinFixtureKey{}, f)
	return pinned, func(c context.Context) error {
		f.finishes++
		actual, _ := auth.ConsentBindingFromContext(c)
		if c.Value(credentialScopePinFixtureKey{}) != f || actual != binding {
			f.t.Fatal("retirement changed pinned process/consent context")
		}
		return c.Err()
	}, nil
}

func exerciseCredentialPreflightRetirement(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, mode string) {
	t.Helper()
	old := f.session
	if old.protected != nil || old.preparation == nil || old.protectionScope.PreparationID != "" || len(old.attempts) != 0 || f.fills != 0 || f.submits != 0 {
		t.Fatal("fixture is not a failed preflight before source capture")
	}
	f.preflightIdle = mode != "preflightRetireBusy"
	if mode == "preflightRetireRestart" {
		old.cancel()
		old.selection.Revoke()
		h.credentials.mu.Lock()
		delete(h.credentials.pending, old.id)
		h.credentials.mu.Unlock()
		replacement, e := vault.NewGuardedExposureGate(func(context.Context) error { return nil })
		if e != nil {
			t.Fatal(e)
		}
		h.vaultExposure = replacement
	}
	next, e := h.CredentialPrepare(ctx, p, input)
	if e != nil {
		t.Fatal(e)
	}
	if mode == "preflightRetireBusy" {
		if next.State != "needsNativeAction" || f.preflightRetirements != 0 {
			t.Fatal("busy private input retired preflight", next)
		}
		if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
			t.Fatal("busy preflight lost durable protection", e)
		}
		return
	}
	if next.State != "awaitingPreflight" || next.PreparationID == ref.PreparationID || next.PreparationID == "" || f.preflightRetirements != 1 || f.preflightChecks == 0 {
		t.Fatal("typed zero-attempt preflight did not recover", next, f.preflightChecks, f.preflightRetirements)
	}
	bound := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: input.SessionID, Purpose: input.Purpose})
	e = h.durable.WithCredentialDeliveryComponents(bound, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
		prep, rows, e := h.durable.LoadCredentialRecovery(held, p, ref.PreparationID)
		if e != nil {
			return e
		}
		if prep.ProtectionState != "closed" || prep.Revision != 2 || len(rows) != 0 {
			t.Fatal("preflight retirement fabricated or lost input history")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if f.fills != 0 || f.submits != 0 {
		t.Fatal("preflight retirement dispatched credential input")
	}
}

func TestManualSuccessorCleanupRetainsExactProvenance(t *testing.T) {
	for _, mode := range []string{"gone", "present", "foreign", "missing", "partial"} {
		t.Run(mode, func(t *testing.T) {
			credentialHostFixtureFlow(t, "manualSuccessor", credentialHostFixtureHooks{exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, _ *atomic.Int64) {
				original := f.session
				if r, e := h.CredentialApply(ctx, p, ref); e != nil || r.State != "filled" {
					t.Fatal("fixture fill", r, e)
				}
				if r, e := h.CredentialSubmit(ctx, p, ref); e != nil || r.State != "submitted" {
					t.Fatal("fixture submit", r, e)
				}
				oldRows := append([]data.CredentialDeliveryRecord(nil), original.attempts...)
				bound := auth.WithConsentBinding(ctx, original.consent)
				a := original.authority
				a.Document.DocumentID = "manual-successor"
				a.Document.Generation++
				a.ScopeQualified = true
				a.Evidence.KernelPeerQualified = true
				a.Lease = chrome.Lease{}
				nextBinding := original.binding
				nextBinding.DocumentID = a.Document.DocumentID
				nextBinding.NavigationID = chrome.CredentialNavigationID(a)
				binding, protected, e := original.protected.TransitionDOM(bound, original.binding, func(context.Context) (vault.Binding, error) { return nextBinding, nil })
				if e != nil {
					t.Fatal(e)
				}
				original.binding, original.protected, original.authority = binding, protected, a
				original.manualDOM = true
				original.state = "privacyReady"
				original.stage = "privacyReady"
				original.dom = &credentialDOMState{authority: a, verify: func(context.Context, auth.Principal, model.Surface, bool) error { return nil }}
				original.publishExposure(true)
				if mode == "foreign" {
					original.authority.ClientID = "another-client"
				}
				if mode == "missing" {
					original.authority.Document.DocumentID = ""
				}
				checks, retirements := map[string]int{}, map[string]int{}
				f.scopeAbsent = func(c context.Context, s chrome.CredentialProtectionScope) error {
					if s.PreparationID != ref.PreparationID || s.Origin != input.Surface.Origin {
						t.Fatal("successor escaped preparation/origin")
					}
					checks[s.Identity.DocumentID]++
					if s.Identity.DocumentID == "manual-successor" && mode == "present" {
						return errPrivateCredential
					}
					return c.Err()
				}
				failedOnce := false
				f.scopeRetire = func(c context.Context, s chrome.CredentialProtectionScope) error {
					retirements[s.Identity.DocumentID]++
					if s.Identity.DocumentID == "manual-successor" && mode == "partial" && !failedOnce {
						failedOnce = true
						return errPrivateCredential
					}
					return c.Err()
				}
				result, e := h.CredentialPrepare(ctx, p, input)
				if e != nil {
					t.Fatal(e)
				}
				if mode == "foreign" || mode == "missing" || mode == "present" {
					if result.State != "needsNativeAction" || result.PreparationID != "" || len(retirements) != 0 {
						t.Fatal("unproved successor allowed cleanup", result, retirements)
					}
					if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
						t.Fatal("failed proof changed durable protection", e)
					}
					if mode != "present" && len(checks) != 0 {
						t.Fatal("malformed ownership reached browser")
					}
					return
				}
				if mode == "partial" {
					if result.State != "needsNativeAction" || !failedOnce || h.credentials.pending[ref.PreparationID] != original || !reflect.DeepEqual(original.authority, a) || !original.manualDOM {
						t.Fatal("partial cleanup discarded successor retry evidence", result)
					}
					if _, e := h.vaultExposure.AcquireExposure(); !errors.Is(e, vault.ErrDeliveryProtected) {
						t.Fatal("partial successor cleanup released protection")
					}

					e = h.durable.WithCredentialDeliveryComponents(bound, p, func(c context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
						prep, rows, e := h.durable.LoadCredentialRecovery(c, p, ref.PreparationID)
						if e != nil {
							return e
						}
						if prep.ProtectionState != "closed" || prep.Revision != 2 || len(rows) != len(oldRows) {
							t.Fatal("partial fixture failed before original parent CAS")
						}
						for _, row := range rows {
							if row.ProtectionState != "closed" {
								t.Fatal("partial fixture failed before original child CAS")
							}
						}
						return nil
					})
					if e != nil {
						t.Fatal(e)
					}
					result, e = h.CredentialPrepare(ctx, p, input)
					if e != nil {
						t.Fatal(e)
					}
				}
				if result.State != "awaitingPreflight" || result.PreparationID == ref.PreparationID || checks["manual-successor"] == 0 || retirements["manual-successor"] == 0 {
					t.Fatal("exact successor was not proved and retired", result, checks, retirements)
				}
				e = h.durable.WithCredentialDeliveryComponents(bound, p, func(c context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
					prep, rows, e := h.durable.LoadCredentialRecovery(c, p, ref.PreparationID)
					if e != nil {
						return e
					}
					if prep.ProtectionState != "closed" || len(rows) != len(oldRows) {
						t.Fatal("original history changed")
					}
					originals := map[string]data.CredentialDeliveryRecord{}
					for _, row := range oldRows {
						originals[row.AttemptID] = row
					}
					for _, row := range rows {
						old, ok := originals[row.AttemptID]
						if !ok {
							t.Fatal("missing or duplicate immutable attempt")
						}
						delete(originals, row.AttemptID)
						old.ProtectionState = "closed"
						old.Revision++
						old.UpdatedAt = row.UpdatedAt
						if row != old {
							actual, expected := reflect.ValueOf(row), reflect.ValueOf(old)
							var changed []string
							for j := 0; j < actual.NumField(); j++ {
								if !reflect.DeepEqual(actual.Field(j).Interface(), expected.Field(j).Interface()) {
									changed = append(changed, actual.Type().Field(j).Name)
								}
							}
							t.Fatalf("successor changed immutable delivery fields: %v", changed)
						}
					}
					if len(originals) != 0 {
						t.Fatal("cleanup removed original attempt")
					}
					return nil
				})
				if e != nil {
					t.Fatal(e)
				}
				f.session = h.credentials.pending[result.PreparationID]
				ready, e := h.CredentialStatus(ctx, p, gateway.CredentialRefInput{SessionID: input.SessionID, PreparationID: result.PreparationID})
				if e != nil || ready.State != "ready" || f.fills != 1 || f.submits != 1 {
					t.Fatal("new candidate blocked or old input replayed", ready, e)
				}
			}})
		})
	}
}
