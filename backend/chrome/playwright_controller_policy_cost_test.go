package chrome

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/model"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Broker, private DOM admission, controller lifetime authorization and sidecar
// IPC are real. Only the signed OS-peer check and renderer/CDP boundaries are
// supplied by this inert socket fixture; no webpage or credentials are used.
func TestPlaywrightControllerPrivacyStartupUsesScopedPeerIdentity(t *testing.T) {
	p := principal(t, "controller-startup-cost")
	p.ClientID = "controller:" + strings.Repeat("a", 64)
	grant := enrollment(p, "controller-cost")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	d := document(grant, 7)
	publish(t, b, conn, grant, d)
	g, e := NewGateway(b, GatewayOptions{})
	if e != nil {
		t.Fatal(e)
	}
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	b.mu.Lock()
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	c.fixtureOnly = false
	c.grant.TrustScope = TrustScopeProfile
	c.profileQualified = true
	c.scopeQualified = true
	c.executorQualified = true
	c.playwrightRelayVersion = 1
	c.mutationFingerprintVersion = 2
	c.processEvidence = &nativepeer.ChromeProcessEvidence{KernelPeerQualified: true}
	c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"http://localhost:*"}}
	session := &ControllerSession{ID: "current-controller", Origin: "http://localhost:3000", DocumentID: "controller-document", Approved: true, ExpiresAt: time.Now().Add(time.Minute), ctx: lifetime, cancel: stop}
	session.identity = ControllerIdentity{Principal: p, Origin: session.Origin, DocumentID: session.DocumentID, ConversationID: session.ID}
	c.controllerSessions = map[string]*ControllerSession{session.ID: session}
	b.mu.Unlock()
	var full, scopedFull, identity, input atomic.Int32
	b.verifyPeer = func(ctx context.Context, _ *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		full.Add(1)
		if ctx.Value(playwrightPrivacyKey{}) != nil {
			scopedFull.Add(1)
		}
		select {
		case <-time.After(20 * time.Millisecond):
			return *c.processEvidence, nil
		case <-ctx.Done():
			return nativepeer.ChromeProcessEvidence{}, ctx.Err()
		}
	}
	b.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error {
		identity.Add(1)
		return nil
	}
	b.playwright = playwrightTestClient(t, "controllerStartup")
	ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), auth.ConsentBinding{SessionID: "current", GrantID: "grant", Purpose: "fixture"})
	a, c, e := g.controlMetadataSnapshot(ctx, p, model.Surface{Kind: "web", Origin: d.Origin, TabID: d.QualifiedTabID()}, false)
	if e != nil {
		t.Fatal(e)
	}
	a.Lease = Lease{ID: "fixture-lease", Generation: 1}
	g.control = &a
	binding, _ := auth.ConsentBindingFromContext(ctx)
	admission := func(current context.Context) error {
		allowed, e := g.AuthorizeControllerPolicy(current, p)
		if e != nil {
			return e
		}
		defer allowed.Release()
		return allowed.Context.Err()
	}
	b.mu.Lock()
	c.privacy = &credentialPrivacyState{gateway: g, channel: c, conn: c.conn, source: a, authority: a, binding: binding, identity: a.Document.Identity, active: true, published: true, admit: admission}
	b.mu.Unlock()
	go func() {
		for {
			raw, e := ReadFrame(conn)
			if e != nil {
				return
			}
			var frame struct {
				Type, RequestID, RelayID, Method string
				Params                           json.RawMessage
			}
			json.Unmarshal(raw, &frame)
			result := any(map[string]any{})
			switch frame.Type {
			case "playwright.open":
				result = map[string]bool{"opened": true}
			case "playwright.receipt":
				result = map[string]bool{"persisted": true}
			case "playwright.close":
				result = map[string]bool{"closed": true}
			case "playwright.send":
				if playwrightInput(frame.Method, frame.Params) {
					input.Add(1)
				}
			}
			if WriteFrame(conn, map[string]any{"type": "playwright.result", "requestId": frame.RequestID, "relayId": frame.RelayID, "result": result}) != nil {
				return
			}
		}
	}()
	for execution := 0; execution < 2; execution++ {
		scopedBefore, identitiesBefore := scopedFull.Load(), identity.Load()
		current, cancel := context.WithTimeout(ctx, 4*time.Second)
		current = context.WithValue(current, playwrightControlCheckKey{}, func(check context.Context) error { return g.VerifyControl(check, p, a) })
		command := Command{Action: "element.press", Identity: d.Identity, Locator: &Locator{Strategy: "id", Value: "fixture", Exact: true}, AttemptID: strings.Repeat(string(rune('b'+execution)), 64), FingerprintVersion: 2, ControlLease: &a.Lease}
		started := time.Now()
		reply, e := b.callPrepared(current, c, command, true, func(Command) (BindingCommit, error) {
			return BindingCommit{BindingID: strings.Repeat("d", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
		}, func() error { return g.VerifyControl(current, p, a) })
		cancel()
		if e != nil || reply.DispatchState != "dispatched" {
			t.Fatal("controller operation failed", e)
		}
		delta := scopedFull.Load() - scopedBefore
		if delta != 2 || identity.Load()-identitiesBefore < 60 {
			t.Fatalf("per-execution full/scoped checks=%d/%d, want2 and continued identity checks", delta, identity.Load()-identitiesBefore)
		}
		t.Logf("execution%d fullPeerChecks%d scopedIdentityChecks%d elapsedMs%d", execution, delta, identity.Load()-identitiesBefore, time.Since(started).Milliseconds())
	}
	if input.Load() != 2 {
		t.Fatal("execution skipped or replayed input")
	}
	outside := full.Load()
	allowed, e := g.AuthorizeControllerPolicy(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	allowed.Release()
	if full.Load() != outside+1 {
		t.Fatal("scoped proof leaked beyond execution")
	}
}

func TestScopedControllerPolicyRechecksRevocationAtEveryAdmission(t *testing.T) {
	for _, mode := range []string{"current", "disabledDuringProbe", "originRemovedDuringProbe", "cancelledDuringProbe", "identityChanged", "completed"} {
		t.Run(mode, func(t *testing.T) {
			f := newReadFixture(t)
			p := f.p
			p.ClientID = "controller:" + strings.Repeat("a", 64)
			ctx := auth.WithPrincipal(context.Background(), p)
			life, cancel := context.WithCancel(context.Background())
			defer cancel()
			b := f.g.broker
			b.mu.Lock()
			c := b.channels[channelKey("p1", "b1")]
			c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"http://localhost:*"}}
			s := &ControllerSession{ID: "current", Origin: "http://localhost:3000", DocumentID: "controller-document", Approved: true, ExpiresAt: time.Now().Add(time.Minute), ctx: life, cancel: cancel}
			s.identity = ControllerIdentity{Principal: p, Origin: s.Origin, DocumentID: s.DocumentID, ConversationID: s.ID}
			c.controllerSessions = map[string]*ControllerSession{s.ID: s}
			command := Command{RequestID: "original", AttemptID: "original-attempt", Identity: c.documents[0].Identity, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash}
			execution := &playwrightExecution{command: command, actor: p, conn: c.conn, processEvidence: c.processEvidence}
			c.playwright = execution
			c.pending[command.RequestID] = &pending{playwright: true, command: command}
			if mode == "completed" {
				c.playwright = nil
			}
			b.mu.Unlock()
			full, probes := 0, 0
			b.verifyPeer = func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
				full++
				return *c.processEvidence, nil
			}
			b.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error {
				probes++
				b.mu.Lock()
				defer b.mu.Unlock()
				switch mode {
				case "disabledDuringProbe":
					c.controllerPolicy.Enabled = false
				case "originRemovedDuringProbe":
					c.controllerPolicy.Origins = nil
				case "cancelledDuringProbe":
					cancel()
				case "identityChanged":
					return auth.ErrUnauthorized
				}
				return nil
			}
			scoped := context.WithValue(ctx, playwrightPrivacyKey{}, execution)
			authorization, e := f.g.AuthorizeControllerPolicy(scoped, p)
			if (e == nil) != (mode == "current") || full != 0 {
				t.Fatal("scoped controller authority stale or fell back to full trust", mode, e)
			}
			if mode == "current" {
				authorization.Release()
				if probes != 1 {
					t.Fatal("fresh kernel identity not checked")
				}
			} else if authorization != nil {
				t.Fatal("revoked controller received authorization")
			}
			if f.mutations.Load() != 0 {
				t.Fatal("policy proof dispatched input")
			}
		})
	}
}
