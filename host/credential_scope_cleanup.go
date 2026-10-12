package host

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

func protectionAbsenceSources(p auth.Principal, snapshot durable.CredentialProtection) ([]chrome.CredentialProtectionScope, error) {
	prep := snapshot.Preparation
	if prep.Namespace != p.Namespace || prep.ClientID != p.ClientID || prep.PreparationID != snapshot.Scope.PreparationID || prep.Origin != snapshot.Scope.Origin || prep.ProtectionState != "held" && prep.ProtectionState != "closed" || len(snapshot.Attempts) > 512 {
		return nil, errPrivateCredential
	}
	var sources []chrome.CredentialProtectionScope
	if snapshot.Scope.Exact() {
		sources = append(sources, sourceFromProtection(p, snapshot))
	}
	for _, a := range snapshot.Attempts {
		if a.Namespace != prep.Namespace || a.ClientID != prep.ClientID || a.SessionID != prep.SessionID || a.SelectionID != prep.PreparationID || a.GrantID != prep.GrantID || a.PurposeHash != prep.PurposeHash || a.SelectedRevision != prep.SelectedRevision || a.Origin != prep.Origin || a.ChromeStartToken == "" || a.ProfileChannel == "" || a.BrowserInstance == "" || a.TabID <= 0 || a.DocumentID == "" || a.DocumentGeneration < 1 || a.Revision < 1 {
			return nil, errPrivateCredential
		}
		source := chrome.CredentialProtectionScope{PreparationID: prep.PreparationID, Origin: prep.Origin, Identity: chrome.Identity{ProfileChannel: a.ProfileChannel, BrowserInstance: a.BrowserInstance, TabID: a.TabID, FrameID: 0, DocumentID: a.DocumentID, Generation: uint64(a.DocumentGeneration)}, ChromeStartToken: a.ChromeStartToken, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash}
		found := false
		for _, s := range sources {
			found = found || s.Identity.ProfileChannel == source.Identity.ProfileChannel && s.Identity.BrowserInstance == source.Identity.BrowserInstance && s.Identity.TabID == source.Identity.TabID && s.Identity.DocumentID == source.Identity.DocumentID && s.ChromeStartToken == source.ChromeStartToken
		}
		if !found {
			sources = append(sources, source)
		}
	}
	if len(sources) == 0 {
		return nil, errPrivateCredential
	}
	return sources, nil
}

// retireAbsentCredentialSources runs only for explicit new login preparation.
// Ordinary observation never performs cleanup. All source identities, retained
// outcomes and current reusable control consent must be independently verified.
var errOtherCredentialScopeHeld = errors.New("another credential source remains protected")

func credentialScopePreparationReason(err error) string {
	if errors.Is(err, errOtherCredentialScopeHeld) {
		return "scopeOtherLoginHeld"
	}
	return chrome.CredentialProtectionFailureReason(err)
}

func (s *credentialService) retireAbsentCredentialSources(ctx context.Context, p auth.Principal, targetOrigin string) error {
	h := s.host
	backend := h.credentialScopeBrowser()
	if backend == nil {
		return errPrivateCredential
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return h.durable.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
		scopes, e := h.durable.CredentialProtectionScopes(held, p)
		if e != nil {
			return e
		}
		// A failed final absence check may leave only the volatile retired gate. Keep
		// its immutable source available for a later explicit Prepare retry.
		s.mu.Lock()
		items := map[string]*credentialSession{}
		for id, item := range s.pending {
			if item.actor.Namespace == p.Namespace && item.actor.ClientID == p.ClientID {
				items[id] = item
			}
		}
		s.mu.Unlock()
		known := map[string]bool{}
		for _, v := range scopes {
			known[v.Scope.PreparationID] = true
		}
		for id, item := range items {
			item.mu.Lock()
			retained := (item.protected != nil || item.preparation != nil) && item.attention == "scopeSourceRetirement"
			original := item.protectionScope
			if original.PreparationID == "" {
				original = chrome.CredentialProtectionScope{PreparationID: item.id, Origin: item.target.Origin}
			}
			item.mu.Unlock()
			if retained && !known[id] {
				scopes = append(scopes, durable.CredentialProtection{Scope: protectionScopeRecord(p, original)})
			}
		}
		type cleanup struct {
			snapshot      durable.CredentialProtection
			sources       []chrome.CredentialProtectionScope
			lease         *consent.Lease
			preflightOnly bool
			successor     *chrome.CredentialProtectionScope
		}
		work := make([]cleanup, 0, len(scopes))
		defer func() {
			for _, w := range work {
				if w.lease != nil {
					w.lease.Release()
				}
			}
		}()
		current, ok := auth.ConsentBindingFromContext(held)
		if !ok {
			return errPrivateCredential
		}
		for _, snapshot := range scopes {
			if snapshot.Scope.ClientID != p.ClientID || snapshot.Scope.Origin != targetOrigin {
				return errOtherCredentialScopeHeld
			}
			prep, attempts, e := h.durable.LoadCredentialRecovery(held, p, snapshot.Scope.PreparationID)
			if e != nil {
				return e
			}
			snapshot.Preparation = prep
			snapshot.Attempts = attempts
			preflightOnly := !snapshot.Scope.Exact() && len(attempts) == 0
			var sources []chrome.CredentialProtectionScope
			if !preflightOnly {
				sources, e = protectionAbsenceSources(p, snapshot)
				if e != nil {
					return e
				}
			}
			successor, e := manualSuccessorProtection(p, snapshot, items[snapshot.Scope.PreparationID])
			if e != nil {
				return e
			}
			work = append(work, cleanup{snapshot: snapshot, sources: sources, preflightOnly: preflightOnly, successor: successor})
		}
		finishProcesses := func(c context.Context) error { return c.Err() }
		if pin, ok := backend.(interface {
			PinCredentialScopeProcesses(context.Context, auth.Principal, []chrome.CredentialProtectionScope) (context.Context, func(context.Context) error, error)
		}); ok && len(work) > 0 {
			var sources []chrome.CredentialProtectionScope
			for _, w := range work {
				sources = append(sources, w.sources...)
				if w.successor != nil {
					sources = append(sources, *w.successor)
				}
			}
			if len(sources) > 0 {
				pinned, finish, e := pin.PinCredentialScopeProcesses(held, p, sources)
				if e != nil {
					return e
				}
				if pinned == nil || finish == nil {
					return errPrivateCredential
				}
				held = pinned
				finishProcesses = finish
			}
		}
		// Derive current-consent leases from the opaque pinned context so every
		// callback retains both request cancellation and fresh kernel identity checks.
		for i := range work {
			bound := auth.WithConsentBinding(held, auth.ConsentBinding{SessionID: current.SessionID, Purpose: current.Purpose})
			lease, e := h.authorizeConsentOperation(consent.RequireReusableGrant(bound), p, model.Surface{Kind: "web", Origin: work[i].snapshot.Preparation.Origin}, true, consent.Control)
			if e != nil {
				return e
			}
			work[i].lease = lease
		}

		verifyAll := func(c context.Context) error {
			for _, w := range work {
				if w.lease.Context.Err() != nil || h.Runtime.CheckSession(c, p, current.SessionID) != nil {
					return errPrivateCredential
				}
				if w.preflightOnly {
					idle, ok := backend.(credentialPreflightRetirementBrowser)
					if !ok {
						return errPrivateCredential
					}
					if e := idle.VerifyCredentialPreflightIdle(c, p, w.snapshot.Preparation.PreparationID, w.snapshot.Preparation.Origin); e != nil {
						return e
					}
				}
				for _, source := range w.sources {
					if e := backend.VerifyCredentialScopeAbsent(c, p, source); e != nil {
						return e
					}
				}
				if w.successor != nil {
					if e := backend.VerifyCredentialScopeAbsent(c, p, *w.successor); e != nil {
						return e
					}
				}
			}
			return c.Err()
		}
		if e = verifyAll(held); e != nil {
			return e
		}
		for _, w := range work {
			working := w.lease.Context
			retire := func(c context.Context) error {
				if w.preflightOnly {
					if e := h.retireCredentialPreflightRows(c, p, w.snapshot, verifyAll); e != nil {
						return e
					}
				} else if e := h.retireCredentialSourceRows(c, p, w.snapshot, w.sources, verifyAll); e != nil {
					return e
				}
				if w.successor != nil {
					if e := backend.RetireAbsentCredentialScope(c, p, *w.successor); e != nil {
						return e
					}
				}
				// A final signed-process failure retains the Vault gate, even after the
				// protection-only durable transition. A later explicit Prepare can retry.
				return finishProcesses(c)
			}
			item := items[w.snapshot.Scope.PreparationID]
			if item != nil {
				item.mu.Lock()
				if item.actor.Namespace != p.Namespace || item.actor.ClientID != p.ClientID {
					item.mu.Unlock()
					return errPrivateCredential
				}
				if item.cancel != nil {
					item.cancel()
				}
				if item.selection != nil {
					item.selection.Revoke()
				}
				item.dom = nil
				item.state = "needsNativeAction"
				item.attention = "scopeSourceRetirement"
				var recoverErr error
				if item.protected != nil {
					item.protected.Retire()
					recoverErr = item.protected.RecoverRetired(working, verifyAll, retire)
				} else if item.preparation != nil {
					item.preparation.Retire()
					recoverErr = item.preparation.RecoverRetired(working, verifyAll, retire)
				} else {
					recoverErr = vault.ErrRetiredDeliveryAbsent
				}
				item.mu.Unlock()
				if recoverErr != nil && !errors.Is(recoverErr, vault.ErrRetiredDeliveryAbsent) {
					return recoverErr
				}
				if errors.Is(recoverErr, vault.ErrRetiredDeliveryAbsent) {
					if e = retire(working); e != nil {
						return e
					}
				}
				s.mu.Lock()
				if s.pending[item.id] == item {
					delete(s.pending, item.id)
				}
				s.mu.Unlock()
			} else {
				release, e := h.vaultExposure.AcquireExposureContext(working)
				if e != nil {
					return e
				}
				e = retire(working)
				release()
				if e != nil {
					return e
				}
			}
		}
		if e := verifyAll(held); e != nil {
			return e
		}
		return finishProcesses(held)
	})
}
func (h *Host) retireCredentialSourceRows(ctx context.Context, p auth.Principal, snapshot durable.CredentialProtection, sources []chrome.CredentialProtectionScope, guard func(context.Context) error) error {
	prep, attempts, e := h.durable.LoadCredentialRecovery(ctx, p, snapshot.Scope.PreparationID)
	if e != nil {
		return e
	}
	if prep != snapshot.Preparation || len(attempts) != len(snapshot.Attempts) {
		return errPrivateCredential
	}
	for i := range attempts {
		if attempts[i] != snapshot.Attempts[i] {
			return errPrivateCredential
		}
	}
	if prep.ProtectionState == "closed" {
		for _, a := range attempts {
			if a.ProtectionState != "closed" && !(a.ProtectionState == "retired" && a.DispatchState == "unknown") {
				return errPrivateCredential
			}
		}
		if e := guard(ctx); e != nil {
			return e
		}
		for _, source := range sources {
			if e := h.credentialScopeBrowser().RetireAbsentCredentialScope(ctx, p, source); e != nil {
				return e
			}
		}
		return nil
	}
	records := make([]data.CredentialProtectionScopeRecord, 0, len(sources))
	for _, source := range sources {
		records = append(records, protectionScopeRecord(p, source))
	}
	clean, stop, e := data.WithCredentialSourceAbsenceAuthority(ctx, prep, attempts, records, guard)
	if e != nil {
		return e
	}
	defer stop()
	for _, old := range attempts {
		if old.ProtectionState == "closed" || old.ProtectionState == "retired" && old.DispatchState == "unknown" {
			continue
		}
		next := old
		next.ProtectionState = "closed"
		if old.DispatchState == "unknown" {
			next.ProtectionState = "retired"
		}
		next.Revision++
		next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		bound, revoke, e := data.WithCredentialDeliveryAuthority(clean, data.CredentialDeliveryAuthority{Before: &old, Record: next}, guard)
		if e != nil {
			return e
		}
		e = h.durable.FinishCredentialDelivery(bound, p)
		revoke()
		if e != nil {
			return e
		}
	}
	prep.ProtectionState = "closed"
	prep.Revision++
	bound, revoke, e := data.WithCredentialPreparationAuthority(clean, prep, guard)
	if e != nil {
		return e
	}
	defer revoke()
	if e = h.durable.CloseCredentialPreparation(bound, p); e != nil {
		return e
	}
	for _, source := range sources {
		if e = h.credentialScopeBrowser().RetireAbsentCredentialScope(bound, p, source); e != nil {
			return e
		}
	}
	return nil
}

type credentialPreflightRetirementBrowser interface {
	VerifyCredentialPreflightIdle(context.Context, auth.Principal, string, string) error
	RetireCredentialPreflight(context.Context, auth.Principal, string, string) error
}

func (h *Host) retireCredentialPreflightRows(ctx context.Context, p auth.Principal, snapshot durable.CredentialProtection, guard func(context.Context) error) error {
	backend, ok := h.credentialScopeBrowser().(credentialPreflightRetirementBrowser)
	if !ok || snapshot.Scope.Exact() || len(snapshot.Attempts) != 0 {
		return errPrivateCredential
	}
	prep, attempts, e := h.durable.LoadCredentialRecovery(ctx, p, snapshot.Scope.PreparationID)
	if e != nil || prep != snapshot.Preparation || len(attempts) != 0 {
		return errPrivateCredential
	}
	if prep.ProtectionState == "closed" {
		if e = guard(ctx); e != nil {
			return e
		}
		return backend.RetireCredentialPreflight(ctx, p, prep.PreparationID, prep.Origin)
	}
	clean, stop, e := data.WithCredentialPreflightCleanupAuthority(ctx, prep, guard)
	if e != nil {
		return e
	}
	defer stop()
	prep.ProtectionState = "closed"
	prep.Revision++
	bound, revoke, e := data.WithCredentialPreparationAuthority(clean, prep, guard)
	if e != nil {
		return e
	}
	defer revoke()
	if e = h.durable.CloseCredentialPreparation(bound, p); e != nil {
		return e
	}
	return backend.RetireCredentialPreflight(bound, p, prep.PreparationID, prep.Origin)
}

// A manual privacy successor is volatile, independently qualified Host state.
// It supplements absence/retirement only; original durable provenance stays A.
// Retain it after partial cleanup so an explicit retry must prove B absent again.
func manualSuccessorProtection(p auth.Principal, snapshot durable.CredentialProtection, item *credentialSession) (*chrome.CredentialProtectionScope, error) {
	if item == nil {
		return nil, nil
	}
	item.mu.Lock()
	defer item.mu.Unlock()
	if !item.manualDOM {
		return nil, nil
	}
	a := item.authority
	prep := snapshot.Preparation
	if item.actor.Namespace != p.Namespace || item.actor.ClientID != p.ClientID || item.id != prep.PreparationID || item.target.Account != prep.PreparationID || item.target.Origin != prep.Origin || item.uncertain || item.protected == nil || item.binding.Target != item.target || item.binding.SessionID != item.consent.SessionID || item.binding.DocumentID != a.Document.DocumentID || item.binding.NavigationID != chrome.CredentialNavigationID(a) || a.Owner != p.Namespace || a.ClientID != p.ClientID || a.Document.Origin != prep.Origin || !a.ScopeQualified || !a.Evidence.KernelPeerQualified || a.Document.TabID <= 0 || a.Document.FrameID != 0 || a.Document.Generation == 0 || a.Document.DocumentID == "" || a.Document.ProfileChannel == "" || a.Document.BrowserInstance == "" || a.Evidence.ChromeParent.StartToken == "" || a.BrokerEpoch == "" || a.ChannelEpoch == "" || len(a.ScopeHash) != 64 {
		return nil, errPrivateCredential
	}
	if raw, e := hex.DecodeString(a.ScopeHash); e != nil || len(raw) != 32 || a.Document.TabID > 2147483647 || a.Document.Generation > 9007199254740991 || len(snapshot.Attempts) == 0 {
		return nil, errPrivateCredential
	}
	for _, value := range []string{a.Document.DocumentID, a.Document.ProfileChannel, a.Document.BrowserInstance, a.Evidence.ChromeParent.StartToken, a.BrokerEpoch, a.ChannelEpoch} {
		if len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
			return nil, errPrivateCredential
		}
	}
	for _, row := range snapshot.Attempts {
		if row.DispatchState != "dispatched" || row.ProfileChannel != a.Document.ProfileChannel || row.BrowserInstance != a.Document.BrowserInstance || row.DocumentID == a.Document.DocumentID {
			return nil, errPrivateCredential
		}
	}
	return &chrome.CredentialProtectionScope{PreparationID: prep.PreparationID, Identity: a.Document.Identity, Origin: prep.Origin, ChromeStartToken: a.Evidence.ChromeParent.StartToken, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash}, nil
}
