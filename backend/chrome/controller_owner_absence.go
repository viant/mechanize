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

var ErrCredentialSourceInputBusy = scopeFailure("scopePreflightBusy")
var ErrCredentialSourcePresent = scopeFailure("scopeSourcePresent")

// VerifyCredentialSourceIdle distinguishes registered controllers/dormant
// privacy state from actual input. Source absence remains a separate proof.

func (g *Gateway) VerifyCredentialSourceIdle(ctx context.Context, p auth.Principal) error {
	actual, e := auth.FromContext(ctx)
	if g == nil || g.broker == nil || e != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || authorize(ctx, p, true) != nil {
		return auth.ErrUnauthorized
	}
	b := g.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return scopeFailure("scopeChanged")
	}
	if len(b.lane) != 0 {
		return ErrCredentialSourceInputBusy
	}
	for _, c := range b.channels {
		if c.grant.Principal.Namespace != p.Namespace {
			continue
		}
		if c.lifecycleInhibited || c.lifecycleGuard != nil || c.privateInspection != nil || c.privateCredential != nil || c.privateAdvance != nil || c.privacyPending != nil || c.manualPending != nil || c.manualTransition != nil || (c.protectionPending != nil && !ownedCleanupScopeRPC(ctx, p, b, c)) || c.playwright != nil || c.openOriginPending != nil || len(c.pending) != 0 || len(c.unknown) != 0 {
			return ErrCredentialSourceInputBusy
		}
	}
	return ctx.Err()
}

// One source-absence/retirement RPC belonging to this exact process pin is proof
// work, not input. Other requests and every actual mutation remain busy.
func ownedCleanupScopeRPC(ctx context.Context, p auth.Principal, b *Broker, c *channel) bool {
	pin, ok := ctx.Value(credentialScopeProcessKey{}).(*credentialScopeProcessPin)
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if !ok || pin == nil || !bound || pin.broker != b || pin.owner != p.Namespace || pin.client != p.ClientID || pin.binding != binding {
		return false
	}
	expected, ok := pin.channels[c]
	if !ok || expected.conn != c.conn || expected.evidence != c.processEvidence || expected.brokerEpoch != b.epoch || expected.channelEpoch != c.epoch || expected.scopeHash != c.scopeHash {
		return false
	}
	pending := c.protectionPending
	if pending == nil || pending.conn != c.conn || pending.request.Mode != "absent" && pending.request.Mode != "retire" {
		return false
	}
	for _, source := range pin.sources {
		if pending.request.PreparationID == source.PreparationID && pending.request.SourceIdentity == source.Identity && pending.request.SourceOrigin == source.Origin && pending.request.BrokerEpoch == b.epoch && pending.request.ChannelEpoch == c.epoch && pending.request.ScopeHash == c.scopeHash {
			return true
		}
	}
	return false
}
