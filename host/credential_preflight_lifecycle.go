package host

import (
	"context"
	"strings"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
)

// A broker restart loses old controller identities, not their privacy ledger.
// Only an origin-only zero-child abandoned preparation may use this lifecycle
// repair. Exact sources and any attempt stay behind their existing absence proof.
func (s *credentialService) retireAbandonedControllerPreflight(ctx context.Context, p auth.Principal, snapshot durable.CredentialProtection) error {
	h := s.host
	backend, ok := h.credentialScopeBrowser().(credentialPreflightRetirementBrowser)
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if !ok || !bound || snapshot.Scope.Exact() || !strings.HasPrefix(snapshot.Scope.ClientID, "controller:") {
		return errOtherCredentialScopeHeld
	}
	guard := func(c context.Context) error {
		if c.Err() != nil || h.checkCredentialSession(c, p, binding.SessionID) != nil {
			return errPrivateCredential
		}
		s.mu.Lock()
		live := s.pending[snapshot.Scope.PreparationID] != nil
		s.mu.Unlock()
		if live {
			return errOtherCredentialScopeHeld
		}
		return backend.VerifyCredentialPreflightIdle(c, p, snapshot.Scope.PreparationID, snapshot.Scope.Origin)
	}
	sealed, revoke, e := data.WithCredentialPreflightLifecycleAuthority(ctx, snapshot.Scope, guard)
	if e != nil {
		return e
	}
	defer revoke()
	prep, children, e := h.durable.LoadCredentialRecovery(sealed, p, snapshot.Scope.PreparationID)
	if e != nil || len(children) != 0 || prep.Namespace != snapshot.Scope.Namespace || prep.ClientID != snapshot.Scope.ClientID || prep.Origin != snapshot.Scope.Origin || prep.ProtectionState != "held" || prep.Revision != 1 {
		return errOtherCredentialScopeHeld
	}
	snapshot.Preparation = prep
	snapshot.Attempts = children
	return h.retireCredentialPreflightRows(sealed, p, snapshot, guard)
}

var _ credentialPreflightRetirementBrowser = (*chrome.Gateway)(nil)
