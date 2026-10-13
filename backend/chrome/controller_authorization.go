package chrome

import (
	"context"
	"time"

	"github.com/viant/mechanize/auth"
)

// ControllerAuthorization is an internal lifetime reservation for a connection
// admitted by the saved trusted-origin policy. No tool JSON can construct it.
// Host ceilings, owned operation sessions, private exposure and input receipts
// remain independent checks.
type ControllerAuthorization struct {
	Context   context.Context
	ExpiresAt time.Time
	Release   func()
}

func (g *Gateway) AuthorizeControllerPolicy(ctx context.Context, p auth.Principal) (*ControllerAuthorization, error) {
	if g == nil || g.broker == nil || ctx.Err() != nil {
		return nil, auth.ErrUnauthorized
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || (!p.HasScope("desktop:observe") && !p.HasScope("desktop:control")) || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || auth.NativeHuman(ctx) {
		return nil, auth.ErrUnauthorized
	}
	b := g.broker
	b.mu.Lock()
	var channel *channel
	var held *ControllerSession
	for _, c := range b.channels {
		for _, s := range c.controllerSessions {
			if s.identity.Principal.Namespace == p.Namespace && s.identity.Principal.ClientID == p.ClientID {
				if held != nil {
					b.mu.Unlock()
					return nil, auth.ErrUnauthorized
				}
				channel, held = c, s
			}
		}
	}
	valid := func() bool {
		return channel != nil && held != nil && channel.grant.Principal.Namespace == p.Namespace && (!p.HasScope("desktop:control") || channel.grant.Principal.HasScope("desktop:control")) && (channel.grant.Principal.HasScope("desktop:observe") || channel.grant.Principal.HasScope("desktop:control")) && !b.closed && channel.conn != nil && channelScopeQualified(channel) && !channel.controllerCleanupPending && channel.controllerSessions[held.ID] == held && held.ctx != nil && held.ctx.Err() == nil && held.Approved && held.ExpiresAt.After(time.Now()) && channel.controllerPolicy.Enabled && controllerPolicyMatches(channel.controllerPolicy.Origins, held.Origin) && held.identity.Origin == held.Origin && held.identity.DocumentID == held.DocumentID
	}
	if !valid() {
		b.mu.Unlock()
		return nil, auth.ErrUnauthorized
	}
	conn, epoch := channel.conn, channel.epoch
	b.mu.Unlock()
	if b.verifyChannelProcess(ctx, channel, false) != nil {
		return nil, auth.ErrUnauthorized
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !valid() || channel.conn != conn || channel.epoch != epoch || ctx.Err() != nil {
		return nil, auth.ErrUnauthorized
	}
	bound, cancel := context.WithDeadline(ctx, held.ExpiresAt)
	stop := context.AfterFunc(held.ctx, cancel)
	return &ControllerAuthorization{Context: bound, ExpiresAt: held.ExpiresAt, Release: func() { stop(); cancel() }}, nil
}
