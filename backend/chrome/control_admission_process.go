package chrome

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"net"
)

type controlAdmissionProcessKey struct{}

// This snapshot belongs only to AdmitControlWithStatus's already bounded context.
// Its authority/evidence came from controlSnapshot's full signed verification;
// it is never returned, persisted, reused by later dispatch, or refreshed by TTL.
type controlAdmissionProcess struct {
	authority      ControlAuthority
	channel        *channel
	conn           net.Conn
	evidence       *nativepeer.ChromeProcessEvidence
	binding        auth.ConsentBinding
	bindingPresent bool
}

func (g *Gateway) admissionProcessContext(ctx context.Context, a ControlAuthority, c *channel) (context.Context, error) {
	b := g.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	// Older/fixture transports keep their original full verification path.
	if c == nil || c.fixtureOnly || c.processEvidence == nil || b.verifyPeerIdentity == nil {
		return ctx, nil
	}
	binding, bound := auth.ConsentBindingFromContext(ctx)
	proof := &controlAdmissionProcess{authority: a, channel: c, conn: c.conn, evidence: c.processEvidence, binding: binding, bindingPresent: bound}
	if !b.admissionProcessCurrentLocked(ctx, c, proof) {
		return ctx, channelProcessError("channelChanged", nil)
	}
	return context.WithValue(ctx, controlAdmissionProcessKey{}, proof), nil
}
func (b *Broker) admissionProcessCurrentLocked(ctx context.Context, c *channel, proof *controlAdmissionProcess) bool {
	actual, e := auth.FromContext(ctx)
	binding, bound := auth.ConsentBindingFromContext(ctx)
	a := proof.authority
	return ctx.Err() == nil && bound == proof.bindingPresent && (!bound || binding == proof.binding) && e == nil && actual.Validate() == nil && actual.Namespace == a.Owner && actual.ClientID == a.ClientID && c == proof.channel && !b.closed && c.conn != nil && c.conn == proof.conn && c.processEvidence != nil && c.processEvidence == proof.evidence && c.processEvidence.NativeHost == a.Evidence.NativeHost && c.processEvidence.ChromeParent == a.Evidence.ChromeParent && c.processEvidence.KernelPeerQualified && !c.fixtureOnly && channelScopeQualified(c) && c.executorQualified && !c.lifecycleInhibited && b.epoch == a.BrokerEpoch && c.epoch == a.ChannelEpoch && c.scopeHash == a.ScopeHash && c.grant.Principal.Namespace == a.Owner && c.grant.ExtensionOrigin == a.ExtensionOrigin && c.grant.TrustScope == a.TrustScope && c.profileQualified == a.ProfileQualified && c.grant.AllWebsites == a.AllWebsites
}
func (b *Broker) checkAdmissionProcessIdentity(ctx context.Context, c *channel, proof *controlAdmissionProcess, revoke bool) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	b.mu.Lock()
	valid := b.admissionProcessCurrentLocked(ctx, c, proof)
	b.mu.Unlock()
	if !valid {
		return channelProcessError("channelChanged", nil)
	}
	unix, ok := proof.conn.(*net.UnixConn)
	if !ok {
		return channelProcessError("nativeChannelUnavailable", nil)
	}
	if e := b.verifyPeerIdentity(ctx, unix, proof.authority.Evidence); e != nil {
		if revoke && ctx.Err() == nil {
			_ = proof.conn.Close()
		}
		return errors.Join(e, channelProcessError("processVerificationUnavailable", nil))
	}
	b.mu.Lock()
	valid = b.admissionProcessCurrentLocked(ctx, c, proof)
	b.mu.Unlock()
	if !valid {
		return channelProcessError("channelChanged", nil)
	}
	return ctx.Err()
}
