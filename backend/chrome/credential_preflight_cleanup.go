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
		if c.privateInspection != nil || c.privateCredential != nil || c.privateFlow != nil || c.privateAdvance != nil || c.privacy != nil || c.privacyPending != nil || c.manualTransition != nil || c.manualPending != nil || c.protectionPending != nil || c.playwright != nil || len(c.pending) > 0 || len(c.unknown) > 0 {
			return scopeFailure("scopePreflightBusy")
		}
	}
	return ctx.Err()
}
func (g *Gateway) RetireCredentialPreflight(ctx context.Context, p auth.Principal, preparationID, origin string) error {
	return g.VerifyCredentialPreflightIdle(ctx, p, preparationID, origin)
}
