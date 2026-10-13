package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
	"strings"
)

// VerifyControllerOwnerAbsent reads only broker-owned lifecycle state. It does
// not mint the old identity, accept wire absence claims or clear any receipt.
func (g *Gateway) VerifyControllerOwnerAbsent(ctx context.Context, p auth.Principal, client string) error {
	if g == nil || g.broker == nil || authorize(ctx, p, true) != nil || !strings.HasPrefix(client, "controller:") || !fingerprintV2Hash.MatchString(strings.TrimPrefix(client, "controller:")) {
		return auth.ErrUnauthorized
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
		if c.controllerCleanupPending {
			return scopeFailure("scopeChanged")
		}
		for _, s := range c.controllerSessions {
			if s.identity.Principal.ClientID == client {
				return scopeFailure("scopeChanged")
			}
		}
	}
	return ctx.Err()
}
