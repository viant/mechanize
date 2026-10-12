package host

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	gateway "github.com/viant/mechanize/mcp"
)

func credentialLifecycleSnapshot(t *testing.T, h *Host, ctx context.Context, p auth.Principal, id string) (data.CredentialPreparationRecord, []data.CredentialDeliveryRecord) {
	t.Helper()
	var prep data.CredentialPreparationRecord
	var attempts []data.CredentialDeliveryRecord
	err := h.durable.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
		var err error
		prep, attempts, err = h.durable.LoadCredentialRecovery(held, p, id)
		return err
	})
	if err != nil {
		t.Fatal("owned typed lifecycle snapshot unavailable")
	}
	return prep, attempts
}
func prepareForeignLifecycleFixture(t *testing.T, h *Host, p auth.Principal, input gateway.CredentialPrepareInput, clientIDs ...string) (gateway.CredentialResult, auth.Principal, string) {
	t.Helper()
	foreign := p
	foreign.ClientID = "successor-fixture-agent"
	foreign.ClientName = "Successor fixture agent"
	if len(clientIDs) > 1 {
		t.Fatal("one successor identity required")
	}
	if len(clientIDs) == 1 {
		foreign.ClientID = clientIDs[0]
	}
	ctx := auth.WithPrincipal(context.Background(), foreign)
	opened, err := h.Runtime.Open(ctx, "Successor lifecycle fixture")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Runtime.Close(ctx, opened.SessionID) })
	request, err := h.consent.Request(ctx, foreign, opened.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "desktop"}, Modes: []consent.Mode{consent.Control, consent.Observe}, Purpose: input.Purpose, DurationSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	human, err := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowUntilRevoked})
	approved, err := h.consent.NativeRPC(human, "decide", decision)
	if err != nil {
		t.Fatal(err)
	}
	input.SessionID = opened.SessionID
	input.GrantID = approved.(*consent.Grant).ID
	result, err := h.CredentialPrepare(ctx, foreign, input)
	if err != nil {
		t.Fatal("independently authorized successor preparation unavailable")
	}
	return result, foreign, opened.SessionID
}
func TestOriginalOwnerPrepareOnlyCleanupCloseCreatesNoNewDurableHold(t *testing.T) {
	for _, mode := range []string{"known", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			credentialHostFixtureFlow(t, mode, credentialHostFixtureHooks{exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
				cleanupMode := "scopeCleanup"
				if mode == "unknown" {
					cleanupMode = "scopeCleanupUnknown"
				}
				exerciseCredentialScopePolicy(t, h, ctx, p, ref, input, f, cleanupMode, reads)
				var fresh *credentialSession
				for id, item := range h.credentials.pending {
					if id != ref.PreparationID && item.actor.ClientID == p.ClientID && item.consent.SessionID == input.SessionID && item.state == "awaitingPreflight" {
						fresh = item
					}
				}
				if fresh == nil || fresh.preparation != nil || fresh.protected != nil || len(fresh.attempts) != 0 {
					t.Fatal("prepare-only allocated protection or input history")
				}
				scopes, err := h.durable.CredentialProtectionScopes(ctx, p)
				if err != nil || len(scopes) != 0 {
					t.Fatal("prepare-only cleanup left a durable hold")
				}
				// A typed exact-owner recovery read must not find a new preparation row.
				err = h.durable.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
					_, _, e := h.durable.LoadCredentialRecovery(held, p, fresh.id)
					return e
				})
				if err == nil {
					t.Fatal("prepare-only wrote a durable preparation")
				}
				fills, submits, admissions := f.fills, f.submits, f.admissions
				if err = h.Runtime.Close(ctx, input.SessionID); err != nil {
					t.Fatal(err)
				}
				if fresh.done.Err() == nil {
					t.Fatal("closing prepare-only session left private capability active")
				}
				scopes, err = h.durable.CredentialProtectionScopes(ctx, p)
				if err != nil || len(scopes) != 0 {
					t.Fatal("session close invented durable protection")
				}
				result, _, _ := prepareForeignLifecycleFixture(t, h, p, input)
				if result.State != "awaitingPreflight" {
					t.Fatal("successor remained blocked after original owned absence cleanup", result.AttentionCode)
				}
				if f.fills != fills || f.submits != submits || f.admissions != admissions {
					t.Fatal("prepare-only close or successor preparation replayed input/preflight")
				}
			}})
		})
	}
}
func TestOwnedCredentialSessionCloseRetiresOnlyAbsentOriginalSources(t *testing.T) {
	for _, mode := range []string{"known", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			credentialHostFixtureFlow(t, mode, credentialHostFixtureHooks{exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
				_, err := h.CredentialApply(ctx, p, ref)
				if err != nil && mode != "unknown" {
					t.Fatal(err)
				}
				_, before := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				fills, submits, admissions, vaultReads := f.fills, f.submits, f.admissions, reads.Load()
				f.scopeAbsent = func(_ context.Context, s chrome.CredentialProtectionScope) error {
					if s.PreparationID != ref.PreparationID || s.Origin != input.Surface.Origin {
						return errPrivateCredential
					}
					return nil
				}
				if err = h.Runtime.Close(ctx, input.SessionID); err != nil {
					t.Fatal(err)
				}
				scopes, err := h.durable.CredentialProtectionScopes(ctx, p)
				if err != nil || len(scopes) != 0 {
					t.Fatal("absent original source remains durably held after owning session close")
				}
				prep, after := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				if prep.ProtectionState != "closed" || len(after) != len(before) {
					t.Fatal("lifecycle cleanup removed history or failed to close protection")
				}
				for i, row := range after {
					old := before[i]
					immutable := row
					immutable.ProtectionState, immutable.Revision, immutable.UpdatedAt = old.ProtectionState, old.Revision, old.UpdatedAt
					if immutable != old {
						t.Fatal("lifecycle cleanup changed immutable input knowledge")
					}
					if row.DispatchState == "unknown" && row.ProtectionState != "retired" {
						t.Fatal("UNKNOWN was resolved instead of protection-only retirement")
					}
				}
				if f.fills != fills || f.submits != submits || f.admissions != admissions || reads.Load() != vaultReads {
					t.Fatal("session lifecycle cleanup performed input, preflight, or Vault reads")
				}
				result, _, _ := prepareForeignLifecycleFixture(t, h, p, input)
				if result.State != "awaitingPreflight" {
					t.Fatal("successor stayed blocked after original lifecycle cleanup", result.AttentionCode)
				}
			}})
		})
	}
}

func TestOwnedCredentialCloseDoesNotRetireUnprovedOrRevokedSources(t *testing.T) {
	for _, kind := range []string{"sourcePresent", "lateAbsenceFailure", "revokedConsent", "foreignClose", "canceledClose"} {
		t.Run(kind, func(t *testing.T) {
			credentialHostFixtureFlow(t, "known", credentialHostFixtureHooks{exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
				if _, err := h.CredentialApply(ctx, p, ref); err != nil {
					t.Fatal(err)
				}
				beforePrep, before := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				fills, submits, admissions, vaultReads := f.fills, f.submits, f.admissions, reads.Load()
				checks := 0
				f.scopeAbsent = func(context.Context, chrome.CredentialProtectionScope) error {
					checks++
					if kind == "sourcePresent" || kind == "lateAbsenceFailure" && checks > 1 {
						return errPrivateCredential
					}
					return nil
				}
				closing, actor := ctx, p
				if kind == "revokedConsent" {
					human, err := auth.WithNativeHuman(ctx)
					if err != nil {
						t.Fatal(err)
					}
					request, _ := json.Marshal(map[string]any{"grantID": f.session.consent.GrantID})
					if _, err = h.consent.NativeRPC(human, "revoke", request); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "foreignClose" {
					actor.ClientID = "foreign-client"
					closing = auth.WithPrincipal(ctx, actor)
				}
				if kind == "canceledClose" {
					var cancel context.CancelFunc
					closing, cancel = context.WithCancel(ctx)
					cancel()
				}
				err := h.Runtime.Close(closing, input.SessionID)
				if kind == "foreignClose" && err == nil {
					t.Fatal("foreign client closed original owner session")
				}
				afterPrep, after := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				if afterPrep != beforePrep || len(after) != len(before) {
					t.Fatal("unproved lifecycle cleanup changed durable parent/history")
				}
				for i, row := range after {
					if row != before[i] {
						t.Fatal("unproved cleanup rewrote attempt knowledge/protection")
					}
				}
				scopes, err := h.durable.CredentialProtectionScopes(ctx, p)
				if err != nil || len(scopes) != 1 {
					t.Fatal("unproved cleanup released durable source")
				}
				if f.fills != fills || f.submits != submits || f.admissions != admissions || reads.Load() != vaultReads {
					t.Fatal("unproved cleanup performed input/preflight/Vault read")
				}
			}})
		})
	}
}
