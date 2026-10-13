package chrome

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

func TestControllerIdleRenewalKeepsIdentityAndRejectsStaleExpiry(t *testing.T) {
	b := &Broker{epoch: "broker"}
	conn, other := net.Pipe()
	defer conn.Close()
	defer other.Close()
	c := &channel{conn: conn, epoch: "channel", scopeHash: "hash", scopeQualified: true, profileQualified: true, grant: Enrollment{TrustScope: TrustScopeProfile, Principal: auth.Principal{Scopes: []string{"desktop:observe"}}}, controllerPolicy: ControllerPolicy{Enabled: true, Origins: []string{"https://fixture.test"}}}
	s := &ControllerSession{ID: "session", Origin: "https://fixture.test", DocumentID: "document", Approved: true, ExpiresAt: time.Now().Add(controllerIdleTTL)}
	c.controllerSessions = map[string]*ControllerSession{s.ID: s}
	t.Cleanup(func() { b.mu.Lock(); cancelControllerSession(s); b.mu.Unlock(); b.wg.Wait() })
	b.mu.Lock()
	b.initControllerSessionLocked(c, s)
	originalContext, originalIdentity := s.ctx, s.identity
	oldGeneration := s.expiryGeneration
	// Time arithmetic is synthetic: no sleep or timer-duration weakening.
	afterSixMinutes := time.Now().Add(6 * time.Minute)
	b.renewControllerSessionLocked(c, s, afterSixMinutes)
	renewed := s.ExpiresAt
	b.expireControllerSessionLocked(c, s, oldGeneration, afterSixMinutes.Add(controllerIdleTTL))
	b.mu.Unlock()
	if s.ctx != originalContext || s.identity.Principal.ClientID != originalIdentity.Principal.ClientID || s.ctx.Err() != nil || !renewed.Equal(afterSixMinutes.Add(controllerIdleTTL)) {
		t.Fatal("refresh changed identity or stale timeout canceled session")
	}
	request := &controllerRequest{Operation: "connection.status", RequestID: "request", SessionID: s.ID, Origin: s.Origin, DocumentID: s.DocumentID, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, Deadline: time.Now().Add(time.Second).UnixMilli()}
	request.Origin = "https://foreign.test"
	b.controllerReply(c, conn, request)
	if !s.ExpiresAt.Equal(renewed) {
		t.Fatal("invalid origin renewed idle deadline")
	}
	b.mu.Lock()
	b.expireControllerSessionLocked(c, s, s.expiryGeneration, renewed)
	b.mu.Unlock()
	if s.ctx.Err() == nil || c.controllerSessions[s.ID] != nil {
		t.Fatal("idle expiration did not cancel exact owner")
	}
	b.wg.Wait()
}
func TestControllerValidRequestRenewsButExplicitRevokeCancelsSameContext(t *testing.T) {
	b := &Broker{epoch: "broker"}
	conn, other := net.Pipe()
	defer conn.Close()
	defer other.Close()
	c := &channel{conn: conn, epoch: "channel", scopeHash: "hash", scopeQualified: true, profileQualified: true, grant: Enrollment{TrustScope: TrustScopeProfile, Principal: auth.Principal{Scopes: []string{"desktop:observe"}}}, controllerPolicy: ControllerPolicy{Enabled: true, Origins: []string{"https://fixture.test"}}}
	s := &ControllerSession{ID: "session", Origin: "https://fixture.test", DocumentID: "document", Approved: true, ExpiresAt: time.Now().Add(time.Minute)}
	c.controllerSessions = map[string]*ControllerSession{s.ID: s}
	t.Cleanup(func() { b.mu.Lock(); cancelControllerSession(s); b.mu.Unlock(); b.wg.Wait() })
	b.mu.Lock()
	b.initControllerSessionLocked(c, s)
	b.mu.Unlock()
	ctx := s.ctx
	request := &controllerRequest{Operation: "connection.status", RequestID: "request", SessionID: s.ID, Origin: s.Origin, DocumentID: s.DocumentID, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, Deadline: time.Now().Add(time.Second).UnixMilli()}
	before := time.Now()
	result := b.controllerReply(c, conn, request)
	if result["error"] != nil || s.ExpiresAt.Before(before.Add(controllerIdleTTL)) || s.ctx != ctx {
		t.Fatal("valid request did not renew same binding")
	}
	b.mu.Lock()
	cancelControllerSession(s)
	b.mu.Unlock()
	if ctx.Err() != context.Canceled {
		t.Fatal("explicit revoke failed to cancel")
	}
	b.wg.Wait()
}

func TestControllerBrokerCloseCancelsRenewedIdleOwner(t *testing.T) {
	grant := enrollment(principal(t, "idle-close"), "idle-close-channel")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	defer conn.Close()
	b.mu.Lock()
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	s := &ControllerSession{ID: "idle-owner", Origin: "https://fixture.test", DocumentID: "document", Approved: true, ExpiresAt: time.Now().Add(controllerIdleTTL)}
	c.controllerSessions = map[string]*ControllerSession{s.ID: s}
	b.initControllerSessionLocked(c, s)
	b.renewControllerSessionLocked(c, s, time.Now())
	ctx := s.ctx
	b.mu.Unlock()
	t.Cleanup(func() { b.mu.Lock(); cancelControllerSession(s); b.mu.Unlock() })
	if e := b.Close(); e != nil {
		t.Fatal(e)
	}
	if ctx.Err() != context.Canceled {
		t.Fatal("broker close retained controller authority")
	}
	b.mu.Lock()
	stopped := !s.expiryTimer.Stop()
	b.mu.Unlock()
	if !stopped {
		t.Fatal("broker close left idle timer running")
	}
}
