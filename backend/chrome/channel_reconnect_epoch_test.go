package chrome

import (
	"encoding/json"
	"github.com/viant/mechanize/model"
	"net"
	"strings"
	"testing"
)

func TestChannelEpochChangesOnlyOnAuthenticatedReplacementTransport(t *testing.T) {
	g, p, ctx, c, oldConn := setupFixture(t)
	b := g.broker
	b.mu.Lock()
	initialEpoch, challenge := c.epoch, c.executorChallenge
	grant := c.grant
	b.mu.Unlock()
	hello := func(credential string) map[string]any {
		return map[string]any{"type": "hello", "protocolVersion": 1, "workerBuild": 33, "profileChannel": grant.ProfileChannel, "browserInstance": grant.BrowserInstance, "extensionOrigin": grant.ExtensionOrigin, "trustScope": TrustScopeDesktop, "credential": credential}
	}
	doc := Document{Identity: Identity{ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, TabID: 7, DocumentID: "owned-original", Generation: 1}, Origin: grant.Origins[0], MutationFingerprintVersion: 2}
	publish := func(conn net.Conn, challenge string) {
		t.Helper()
		if err := WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": challenge, "mutationFingerprintVersion": 2}); err != nil {
			t.Fatal(err)
		}
		if err := WriteFrame(conn, map[string]any{"type": "documents", "documents": []Document{doc}}); err != nil {
			t.Fatal(err)
		}
		waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.executorQualified && c.inventoryComplete })
	}
	publish(oldConn, challenge)
	authority, _, err := g.controlSnapshot(ctx, p, model.Surface{Kind: "web", Origin: doc.Origin})
	if err != nil {
		t.Fatal(err)
	}
	authority.Lease = Lease{ID: "original-owned-lease", Generation: 1}
	g.controlMu.Lock()
	g.setControlLocked(authority)
	g.controlMu.Unlock()
	// Metadata renewal on the already accepted socket is not a new transport.
	publish(oldConn, challenge)
	b.mu.Lock()
	unchanged := c.epoch == initialEpoch
	b.mu.Unlock()
	if !unchanged {
		t.Fatal("unchanged transport renewed its epoch")
	}
	for _, credential := range []string{"invalid", strings.Repeat("synthetic", 8)} {
		rejected, err := net.Dial("unix", b.listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteFrame(rejected, hello(credential)); err != nil {
			t.Fatal(err)
		}
		raw, err := ReadFrame(rejected)
		rejected.Close()
		if err != nil {
			t.Fatal(err)
		}
		var reply struct{ Type, Code string }
		if json.Unmarshal(raw, &reply) != nil || reply.Type != "nativeHostError" {
			t.Fatal("unauthenticated/busy transport accepted")
		}
		b.mu.Lock()
		unchanged = c.epoch == initialEpoch
		b.mu.Unlock()
		if !unchanged {
			t.Fatal("rejected transport changed the live epoch")
		}
	}
	oldConn.Close()
	waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.conn == nil })
	replacement, err := net.Dial("unix", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err := WriteFrame(replacement, hello(strings.Repeat("synthetic", 8))); err != nil {
		t.Fatal(err)
	}
	raw, err := ReadFrame(replacement)
	if err != nil {
		t.Fatal(err)
	}
	var ack struct{ Type, BrokerEpoch, ChannelEpoch, ExecutorChallenge string }
	if json.Unmarshal(raw, &ack) != nil || ack.Type != "processQualified" || ack.ChannelEpoch == initialEpoch || ack.BrokerEpoch != b.epoch {
		t.Fatal("accepted replacement did not rotate only its channel fence")
	}
	publish(replacement, ack.ExecutorChallenge)
	if err := g.VerifyControl(ctx, p, authority); err == nil {
		t.Fatal("old authority authorized replacement transport")
	}
	if err := WriteFrame(oldConn, map[string]any{"type": "executorPrepared", "executorChallenge": challenge, "mutationFingerprintVersion": 2}); err == nil {
		t.Fatal("old closed connection published authority")
	}
	b.mu.Lock()
	current := c.epoch == ack.ChannelEpoch && c.executorChallenge == ack.ExecutorChallenge
	b.mu.Unlock()
	if !current {
		t.Fatal("old connection replaced the accepted fence")
	}
}
