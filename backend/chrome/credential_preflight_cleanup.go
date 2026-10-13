package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
)

// The Host must additionally prove an exact owned preparation with a complete
// zero-child durable inventory. This method proves only live broker quiescence;
// it cannot retire a lease, clear an outcome or authorize any renderer input.
func (g *Gateway) VerifyCredentialPreflightIdle(ctx context.Context, p auth.Principal, preparationID, origin string) error {
	if g == nil || g.broker == nil || authorize(ctx, p, true) != nil || !fingerprintV2Hash.MatchString(preparationID) || !OrdinaryWebsiteOrigin(origin) || ctx.Err() != nil {
		return scopeFailure("scopeChanged")
	}
	actual, e := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if e != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || !ok || binding.SessionID == "" || binding.GrantID == "" || binding.Purpose == "" || auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	g.controlMu.Lock()
	defer g.controlMu.Unlock()
	if g.control != nil || g.controlRetiring {
		return scopeFailure("scopePreflightBusy")
	}
	b := g.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return scopeFailure("scopeChanged")
	}
	for _, c := range b.channels {
		if c.grant.Principal.Namespace != p.Namespace {
			continue
		}
		if c.privateInspection != nil && (c.privateOwner.Namespace != p.Namespace || c.privateOwner.ClientID != p.ClientID || c.privateConsent != binding || c.privateInspection.lease != nil) {
			return scopeFailure("scopePreflightBusy")
		}
		if c.privateInspection != nil && !c.privateInspection.knownNoInput || c.privateCredential != nil || c.privateFlow != nil || c.privateAdvance != nil || c.privacy != nil || c.privacyPending != nil || c.manualTransition != nil || c.manualPending != nil || c.protectionPending != nil || c.playwright != nil || len(c.pending) > 0 || len(c.unknown) > 0 {
			return scopeFailure("scopePreflightBusy")
		}
	}
	return ctx.Err()
}
func (g *Gateway) RetireCredentialPreflight(ctx context.Context, p auth.Principal, preparationID, origin string) error {
	if err := g.VerifyCredentialPreflightIdle(ctx, p, preparationID, origin); err != nil {
		return err
	}
	g.controlMu.Lock()
	defer g.controlMu.Unlock()
	binding, _ := auth.ConsentBindingFromContext(ctx)
	b := g.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || g.control != nil || g.controlRetiring || ctx.Err() != nil {
		return scopeFailure("scopePreflightBusy")
	}
	for _, c := range b.channels {
		if c.grant.Principal.Namespace != p.Namespace {
			continue
		}
		if c.privateInspection != nil && (c.privateOwner.Namespace != p.Namespace || c.privateOwner.ClientID != p.ClientID || c.privateConsent != binding || c.privateInspection.lease != nil) {
			return scopeFailure("scopePreflightBusy")
		}
		if c.privateInspection != nil && !c.privateInspection.knownNoInput || c.privateCredential != nil || c.privateFlow != nil || c.privateAdvance != nil || c.privacy != nil || c.privacyPending != nil || c.manualTransition != nil || c.manualPending != nil || c.protectionPending != nil || c.playwright != nil || len(c.pending) > 0 || len(c.unknown) > 0 {
			return scopeFailure("scopePreflightBusy")
		}
	}
	for _, c := range b.channels {
		if c.grant.Principal.Namespace != p.Namespace || c.privateInspection == nil || !c.privateInspection.knownNoInput {
			continue
		}
		// Inspection read no values and installed no input lease. Keep the safe
		// pre-existing document metadata; late private replies are wiped in readLoop.
		c.privateInspection = nil
	}
	return nil
}
