package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/engine/durable"
)

// A correlated non-ready inspection has no input lease or delivery children.
// Release that exact admission through existing durable zero-child retirement;
// no page, private field, attempt or historical source is changed.
func (s *credentialService) releaseRejectedPreflight(ctx context.Context, p auth.Principal, item *credentialSession) error {
	backend, ok := s.host.credentialScopeBrowser().(credentialPreflightRetirementBrowser)
	if !ok {
		return errPrivateCredential
	}
	return s.host.durable.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
		// This is a fresh existing-policy check outside any writer transaction;
		// retain its revocation-bound lease throughout all proof and CAS callbacks.
		lease, e := s.host.authorizeConsentOperation(held, p, item.surface, true, consent.Control)
		if e != nil {
			return e
		}
		defer lease.Release()
		held = lease.Context
		item.mu.Lock()
		defer item.mu.Unlock()
		if !item.preflightNoInput {
			return nil
		}
		if item.actor.Namespace != p.Namespace || item.actor.ClientID != p.ClientID || item.preparation == nil || item.protected != nil || item.dom != nil || item.uncertain || len(item.attempts) != 0 || item.fillAttempt != "" || item.submitAttempt != "" {
			return errPrivateCredential
		}
		prep, children, e := s.host.durable.LoadCredentialRecovery(held, p, item.id)
		if e != nil || len(children) != 0 || prep.SessionID != item.consent.SessionID || prep.Origin != item.target.Origin {
			return errPrivateCredential
		}
		guard := func(c context.Context) error {
			if lease.Context.Err() != nil || c.Err() != nil || s.host.Runtime.CheckSession(c, p, item.consent.SessionID) != nil {
				return errPrivateCredential
			}
			return backend.VerifyCredentialPreflightIdle(c, p, item.id, item.target.Origin)
		}
		if e = guard(held); e != nil {
			return e
		}
		// Current consent stays retained through the typed close/readback and
		// volatile gate release; revocation invalidates every guard callback.
		snapshot := durable.CredentialProtection{Preparation: prep, Attempts: children}
		snapshot.Scope.Namespace = prep.Namespace
		snapshot.Scope.ClientID = prep.ClientID
		snapshot.Scope.PreparationID = prep.PreparationID
		snapshot.Scope.Origin = prep.Origin
		item.preparation.Retire()
		e = item.preparation.RecoverRetired(held, guard, func(c context.Context) error { return s.host.retireCredentialPreflightRows(c, p, snapshot, guard) })
		if e != nil {
			return e
		}
		item.preflightNoInput = false
		// Confirmed zero-child retirement has released this volatile gate.
		// Cancel only this old selection; the owned automation session remains
		// open so a fresh explicit Prepare can qualify the current document.
		item.preparation = nil
		if item.cancel != nil {
			item.cancel()
		}
		if item.selection != nil {
			item.selection.Revoke()
		}
		return nil
	})
}
