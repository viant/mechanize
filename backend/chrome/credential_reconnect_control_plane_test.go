package chrome

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestInactivePrivacyAllowsAuthenticatedReplacementControlPlane(t *testing.T) {
	testInactivePrivacyReplacement(t, false)
}

func TestInactivePrivacyReplacementRejectsWrongChallenge(t *testing.T) {
	testInactivePrivacyReplacement(t, true)
}

func testInactivePrivacyReplacement(t *testing.T, wrongChallenge bool) {
	g, p, ctx, source, submit := privacyFixture(t)
	defer g.Close()
	proof, err := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	g.broker.mu.Lock()
	c := g.broker.channels[channelKey(source.Document.ProfileChannel, source.Document.BrowserInstance)]
	old := proof.state
	c.privacy.active = false
	previous := c.conn
	enrollment := c.grant
	g.broker.mu.Unlock()
	previous.Close()
	waitControl(t, func() bool { g.broker.mu.Lock(); defer g.broker.mu.Unlock(); return c.conn == nil })
	peer, err := net.Dial("unix", g.broker.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	hello := map[string]any{"type": "hello", "protocolVersion": 1, "profileChannel": enrollment.ProfileChannel, "browserInstance": enrollment.BrowserInstance, "extensionOrigin": enrollment.ExtensionOrigin, "credential": strings.Repeat("fixture", 8), "profileDirectory": enrollment.ProfileDirectory, "profileLaunchQualified": true, "selectOptionVersion": 1}
	if err = WriteFrame(peer, hello); err != nil {
		t.Fatal(err)
	}
	raw, err := ReadFrame(peer)
	if err != nil {
		t.Fatal(err)
	}
	var ack map[string]any
	if json.Unmarshal(raw, &ack) != nil {
		t.Fatal("invalid fixture acknowledgement")
	}
	challenge := ack["executorChallenge"]
	if wrongChallenge {
		challenge = "wrong-fixture-challenge"
	}
	if err = WriteFrame(peer, map[string]any{"type": "executorPrepared", "executorChallenge": challenge, "mutationFingerprintVersion": 2}); err != nil {
		t.Fatal(err)
	}
	if wrongChallenge {
		waitControl(t, func() bool { g.broker.mu.Lock(); defer g.broker.mu.Unlock(); return c.conn == nil })
		g.broker.mu.Lock()
		defer g.broker.mu.Unlock()
		if c.executorQualified || c.privacy != old {
			t.Fatal("wrong challenge acquired authority or erased protection")
		}
		return
	}
	// The shipped worker publishes this metadata inventory immediately after setup.
	if err = WriteFrame(peer, map[string]any{"type": "documents", "documents": []Document{{Identity: Identity{ProfileChannel: enrollment.ProfileChannel, BrowserInstance: enrollment.BrowserInstance, TabID: 99, DocumentID: "public-successor", Generation: 1}, Origin: enrollment.Origins[0], MutationFingerprintVersion: 2}}, "truncated": false, "capabilities": []string{"observe"}, "inputSemantics": "fixture", "unsupported": []string{}}); err != nil {
		t.Fatal(err)
	}
	waitControl(t, func() bool {
		g.broker.mu.Lock()
		defer g.broker.mu.Unlock()
		return c.conn == nil || c.inventoryComplete
	})
	g.broker.mu.Lock()
	connected := c.conn != nil
	retained := c.privacy == old && !c.privacy.active
	inventory := c.inventoryComplete && len(c.documents) == 1 && c.documents[0].DocumentID == "public-successor"
	g.broker.mu.Unlock()
	if !connected || !retained || !inventory {
		t.Fatalf("inactive private state poisoned replacement setup: connected=%v retained=%v", connected, retained)
	}

	replyDone := make(chan error, 1)
	go func() {
		raw, e := ReadFrame(peer)
		if e != nil {
			replyDone <- e
			return
		}
		var command Command
		if e = json.Unmarshal(raw, &command); e != nil {
			replyDone <- e
			return
		}
		replyDone <- WriteFrame(peer, Reply{RequestID: command.RequestID, Identity: command.Identity, DispatchState: "notDispatched"})
	}()
	identity := Identity{ProfileChannel: enrollment.ProfileChannel, BrowserInstance: enrollment.BrowserInstance, TabID: 99, DocumentID: "public-successor", Generation: 1}
	if _, e := g.broker.call(ctx, c, Command{Action: "observe", Identity: identity}, false); e != nil {
		t.Fatal("fresh public read rejected", e)
	}
	if e := <-replyDone; e != nil {
		t.Fatal(e)
	}
	// Closed attention metadata proves the replacement reader remains alive.
	if err = WriteFrame(peer, map[string]any{"type": "attention", "error": map[string]string{"code": "executorNotQuiescent", "message": "PRIVATE_CANARY"}}); err != nil {
		t.Fatal(err)
	}
	waitControl(t, func() bool {
		g.broker.mu.Lock()
		defer g.broker.mu.Unlock()
		return c.conn == nil || c.attentionCode == "executorNotQuiescent"
	})
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if c.conn == nil || c.executorQualified {
		t.Fatal("attention failed to retain transport and withdraw executor")
	}
}

func TestPrivateControlPlanePassIsClosedAndKeepsActivePrivateExclusion(t *testing.T) {
	peer, oldPeer := net.Pipe()
	defer peer.Close()
	defer oldPeer.Close()
	c := &channel{conn: peer, privacy: &credentialPrivacyState{active: false}}
	prepared := []byte(`{"type":"executorPrepared","executorChallenge":"fixture","mutationFingerprintVersion":2}`)
	attention := []byte(`{"type":"attention","error":{"code":"executorNotQuiescent","message":"PRIVATE_CANARY"}}`)
	for _, raw := range [][]byte{prepared, attention} {
		if !inactivePrivacyControlPlaneFrameLocked(c, raw) {
			t.Fatal("closed metadata lane rejected")
		}
	}
	for _, raw := range [][]byte{[]byte(`{"type":"executorPrepared","nodes":[{"name":"PRIVATE_CANARY"}]}`), []byte(`{"type":"attention","value":"PRIVATE_CANARY"}`), []byte(`{"requestId":"read","nodes":[{"name":"PRIVATE_CANARY"}]}`), []byte(`{"type":"documents","documents":[{"nodes":[{"name":"PRIVATE_CANARY"}]}]}`)} {
		if inactivePrivacyControlPlaneFrameLocked(c, raw) {
			t.Fatal("private DOM frame entered metadata lane")
		}
	}
	c.privacy.active = true
	if inactivePrivacyControlPlaneFrameLocked(c, prepared) {
		t.Fatal("active private exchange bypassed")
	}
	c.privacy.active = false
	c.privateFlow = &credentialFlow{}
	if inactivePrivacyControlPlaneFrameLocked(c, prepared) {
		t.Fatal("current private flow bypassed")
	}
}

func TestInactivePrivacyReplacementExcludesCurrentProtection(t *testing.T) {
	g, _, _, c, _ := setupFixture(t)
	defer g.Close()
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	old := &credentialPrivacyState{}
	c.privacy = old
	if !inactivePrivacyReplacementLocked(c) {
		t.Fatal("prior inactive owner blocked metadata retirement")
	}
	old.active = true
	if inactivePrivacyReplacementLocked(c) {
		t.Fatal("active protection bypassed")
	}
	old.active = false
	old.conn = c.conn
	if inactivePrivacyReplacementLocked(c) {
		t.Fatal("same connection protection bypassed")
	}
	old.conn = nil
	c.privateFlow = &credentialFlow{}
	if inactivePrivacyReplacementLocked(c) {
		t.Fatal("current private exchange bypassed")
	}
}
