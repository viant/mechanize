package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"net"
)

type credentialScopeProcessKey struct{}
type credentialScopeProcessPin struct {
	broker        *Broker
	owner, client string
	binding       auth.ConsentBinding
	channels      map[*channel]credentialScopeChannelPin
}
type credentialScopeChannelPin struct {
	conn                                 net.Conn
	evidence                             *nativepeer.ChromeProcessEvidence
	brokerEpoch, channelEpoch, scopeHash string
}

// PinCredentialScopeProcesses is local to one held cleanup context. Full signed
// verification brackets it; every exchange still checks kernel peer identity and
// performs its fresh Chrome document-absence proof. No TTL or global cache.
func (g *Gateway) PinCredentialScopeProcesses(ctx context.Context, p auth.Principal, sources []CredentialProtectionScope) (context.Context, func(context.Context) error, error) {
	if g == nil || g.broker == nil || authorize(ctx, p, true) != nil {
		return ctx, nil, auth.ErrUnauthorized
	}
	actual, _ := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || actual.ClientID != p.ClientID || len(sources) > 512 {
		return ctx, nil, auth.ErrUnauthorized
	}
	b := g.broker
	pin := &credentialScopeProcessPin{broker: b, owner: p.Namespace, client: p.ClientID, binding: binding, channels: map[*channel]credentialScopeChannelPin{}}
	for _, source := range sources {
		if !validProtectionScope(source) {
			return ctx, nil, scopeFailure("scopeChanged")
		}
		b.mu.Lock()
		c := b.channels[channelKey(source.Identity.ProfileChannel, source.Identity.BrowserInstance)]
		// A disconnected predecessor or a different current Chrome birth is
		// proved absent independently on every Verify call, not by this pin.
		if c == nil || c.conn == nil || c.processEvidence == nil || c.processEvidence.ChromeParent.StartToken != source.ChromeStartToken {
			b.mu.Unlock()
			continue
		}
		if c != nil && (c.grant.Principal.Namespace != p.Namespace || !allowedOrigin(c.grant, source.Origin)) {
			b.mu.Unlock()
			return ctx, nil, auth.ErrUnauthorized
		}
		b.mu.Unlock()
		if c == nil {
			continue
		}
		if _, seen := pin.channels[c]; seen {
			continue
		}
		if b.checkChannelProcess(ctx, c, false) != nil {
			return ctx, nil, scopeFailure("scopeChanged")
		}
		b.mu.Lock()
		pin.channels[c] = credentialScopeChannelPin{conn: c.conn, evidence: c.processEvidence, brokerEpoch: b.epoch, channelEpoch: c.epoch, scopeHash: c.scopeHash}
		b.mu.Unlock()
	}
	pinned := context.WithValue(ctx, credentialScopeProcessKey{}, pin)
	finish := func(final context.Context) error {
		for c, expected := range pin.channels {
			if !b.scopePinCurrent(final, pin, c, expected) || b.checkChannelProcess(final, c, false) != nil || !b.scopePinCurrent(final, pin, c, expected) {
				return scopeFailure("scopeChanged")
			}
		}
		return final.Err()
	}
	return pinned, finish, nil
}
func (b *Broker) scopePinCurrent(ctx context.Context, pin *credentialScopeProcessPin, c *channel, expected credentialScopeChannelPin) bool {
	actual, e := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if ctx.Err() != nil || e != nil || !ok || actual.Namespace != pin.owner || actual.ClientID != pin.client || binding != pin.binding || pin.broker != b {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.closed && c.conn == expected.conn && c.processEvidence == expected.evidence && b.epoch == expected.brokerEpoch && c.epoch == expected.channelEpoch && c.scopeHash == expected.scopeHash && channelScopeQualified(c)
}
func (b *Broker) checkCredentialScopeProcess(ctx context.Context, c *channel) error {
	pin, ok := ctx.Value(credentialScopeProcessKey{}).(*credentialScopeProcessPin)
	if !ok {
		return b.checkChannelProcess(ctx, c, false)
	}
	expected, ok := pin.channels[c]
	if !ok || !b.scopePinCurrent(ctx, pin, c, expected) {
		return scopeFailure("scopeChanged")
	}
	unix, ok := expected.conn.(*net.UnixConn)
	if !ok || expected.evidence == nil {
		return scopeFailure("scopeChanged")
	}
	if b.verifyPeerIdentity == nil {
		return b.checkChannelProcess(ctx, c, false)
	}
	if b.verifyPeerIdentity(ctx, unix, *expected.evidence) != nil || !b.scopePinCurrent(ctx, pin, c, expected) {
		return scopeFailure("scopeChanged")
	}
	return nil
}
