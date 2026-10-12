package chrome

import (
	"context"
	"time"

	"github.com/viant/mechanize/auth"
)

// CredentialRetirementProof is volatile provider evidence, not a transport
// claim. It proves only exact tab closure after a known fill and no submission.
// It never establishes login success, resolves unknown input, or releases
// durable protection. The host must commit cleanup separately before exposure.
type CredentialRetirementProof struct {
	flow    *credentialFlow
	channel *channel
	attempt string
}

// RetireVaultCredential closes the exact protected tab once. The trusted host
// must reserve a distinct durable UNKNOWN cleanup attempt before calling. A lost
// reply cannot be replayed and returns no proof. No credential value is read.
func (g *Gateway) RetireVaultCredential(ctx context.Context, p auth.Principal, a ControlAuthority, fill, attempt string, admit func(context.Context) error) (CredentialRetirementProof, CredentialDeliveryResult, error) {
	var proof CredentialRetirementProof
	result := CredentialDeliveryResult{DispatchState: "notDispatched"}
	if g == nil || g.broker == nil || admit == nil || !fingerprintV2Hash.MatchString(fill) || !fingerprintV2Hash.MatchString(attempt) || fill == attempt {
		return proof, result, errCredentialDelivery
	}
	c := g.controlChannel(a)
	if c == nil {
		return proof, result, errCredentialDelivery
	}
	b := g.broker
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	select {
	case b.lane <- struct{}{}:
		defer func() { <-b.lane }()
	case <-ctx.Done():
		return proof, result, errCredentialDelivery
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil {
		return proof, result, errCredentialDelivery
	}
	b.mu.Lock()
	f := c.privateFlow
	cb, bound := auth.ConsentBindingFromContext(ctx)
	if !bound || f == nil || f.binding != cb || f.poisoned || f.retireAttempt != "" || f.fillAttempt != fill || f.submitConfirmed || f.submitAttempt != "" && f.submitState != "notDispatched" || !sameControl(f.authority, a) || c.conn == nil || c.privateCredential != nil || c.privateAdvance != nil || len(c.pending) != 0 || len(c.unknown) != 0 || c.lifecycleInhibited || c.privateCredentialAttempts == nil || c.privateCredentialAttempts[attempt] || len(c.privateCredentialAttempts) >= 512 {
		b.mu.Unlock()
		return proof, result, errCredentialDelivery
	}
	conn := c.conn
	pending := &credentialDeliveryPending{requestID: newPrivateID(), attemptID: attempt, identity: a.Document.Identity, done: make(chan string, 1), replyType: "credentialRetireResult"}
	f.retireAttempt = attempt
	c.privateCredentialAttempts[attempt] = true
	c.invalidateConsentReconnect()
	c.privateCredential = pending
	c.unknown[attempt] = true
	b.mu.Unlock()
	completed := false
	defer func() {
		if !completed {
			_ = conn.Close()
		}
	}()
	command := map[string]any{"type": "credentialRetire", "requestId": pending.requestID, "attemptId": attempt, "fillAttemptId": fill, "identity": a.Document.Identity, "brokerEpoch": a.BrokerEpoch, "channelEpoch": a.ChannelEpoch, "scopeHash": a.ScopeHash, "controlLease": a.Lease, "deadlineUnixMs": deadline.UnixMilli(), "origin": a.Document.Origin}
	if ctx.Err() != nil || admit(ctx) != nil || g.VerifyControl(ctx, p, a) != nil {
		return proof, result, errCredentialDelivery
	}
	result.DispatchState = "unknown"
	if conn.SetWriteDeadline(deadline) != nil {
		return proof, result, errCredentialDelivery
	}
	err := WriteFrame(conn, command)
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return proof, result, errCredentialDelivery
	}
	select {
	case state := <-pending.done:
		// Exact retirement allows the document inventory entry to disappear;
		// signed process, channel, owner and consent checks still apply.
		if state == "unknown" || admit(ctx) != nil || b.verifyChannelProcess(ctx, c) != nil || g.controlCheck(ctx, p, a, c, true, true) != nil {
			return proof, result, errCredentialDelivery
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if pending.failed || c.privateFlow != f || f.poisoned || c.conn != conn {
			return proof, result, errCredentialDelivery
		}
		c.privateCredential = nil
		delete(c.unknown, attempt)
		result.DispatchState = state
		completed = true
		if state == "dispatched" {
			f.retired = true
			proof = CredentialRetirementProof{flow: f, channel: c, attempt: attempt}
		}
		return proof, result, nil
	case <-ctx.Done():
		return proof, result, errCredentialDelivery
	}
}

// VerifyCredentialRetirement revalidates sealed evidence under its original
// live channel and consent; callers cannot construct a proof from scalar JSON.
func (g *Gateway) VerifyCredentialRetirement(ctx context.Context, p auth.Principal, a ControlAuthority, proof CredentialRetirementProof) error {
	if g == nil || g.broker == nil || proof.flow == nil || proof.channel == nil || proof.attempt == "" {
		return errCredentialDelivery
	}
	c := g.controlChannel(a)
	if c != proof.channel || g.broker.verifyChannelProcess(ctx, c) != nil || g.controlCheck(ctx, p, a, c, true, true) != nil {
		return errCredentialDelivery
	}
	cb, ok := auth.ConsentBindingFromContext(ctx)
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	f := proof.flow
	if !ok || f.binding != cb || c.privateFlow != f || !sameControl(f.authority, a) || f.poisoned || !f.retired || f.retireAttempt != proof.attempt || len(c.unknown) != 0 {
		return errCredentialDelivery
	}
	return ctx.Err()
}
