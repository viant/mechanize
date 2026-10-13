package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	"strings"
)

type credentialControllerAbsenceBrowser interface {
	VerifyControllerOwnerAbsent(context.Context, auth.Principal, string) error
}

// Explicit Prepare may retire an extinct controller's privacy protection only.
// The real successor remains the actor; no old delivery capability is restored.
func (s *credentialService) retireExtinctControllerSource(ctx context.Context, p auth.Principal, snapshot durable.CredentialProtection) error {
	h := s.host
	backend := h.credentialScopeBrowser()
	owners, ok := backend.(credentialControllerAbsenceBrowser)
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if !ok || !bound || !snapshot.Scope.Exact() || !strings.HasPrefix(snapshot.Scope.ClientID, "controller:") {
		return errOtherCredentialScopeHeld
	}
	ownerAbsent := func(c context.Context) error {
		if c.Err() != nil || h.checkCredentialSession(c, p, binding.SessionID) != nil {
			return errPrivateCredential
		}
		s.mu.Lock()
		live := s.pending[snapshot.Scope.PreparationID] != nil
		s.mu.Unlock()
		if live {
			return errOtherCredentialScopeHeld
		}
		return owners.VerifyControllerOwnerAbsent(c, p, snapshot.Scope.ClientID)
	}
	sealed, revoke, e := data.WithCredentialSourceLifecycleAuthority(ctx, snapshot.Scope, ownerAbsent)
	if e != nil {
		return e
	}
	defer revoke()
	prep, children, e := h.durable.LoadCredentialRecovery(sealed, p, snapshot.Scope.PreparationID)
	if e != nil || prep.Namespace != snapshot.Scope.Namespace || prep.ClientID != snapshot.Scope.ClientID || prep.Origin != snapshot.Scope.Origin || prep.PreparationID != snapshot.Scope.PreparationID || prep.ProtectionState != "held" || prep.Revision != 1 {
		return errOtherCredentialScopeHeld
	}
	snapshot.Preparation, snapshot.Attempts = prep, children
	sources, e := protectionAbsenceSourcesForOwner(snapshot)
	if e != nil {
		return e
	}
	guard := func(c context.Context) error {
		if e := ownerAbsent(c); e != nil {
			return e
		}
		for _, source := range sources {
			if e := backend.VerifyCredentialScopeAbsent(c, p, source); e != nil {
				return e
			}
		}
		return c.Err()
	}
	if e = guard(sealed); e != nil {
		return e
	}
	release, e := h.vaultExposure.AcquireExposureContext(sealed)
	if e != nil {
		return e
	}
	defer release()
	return h.retireCredentialSourceRows(sealed, p, snapshot, sources, guard)
}
