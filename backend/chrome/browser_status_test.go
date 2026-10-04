package chrome

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
)

func TestBrowserStatusOwnedMetadataAndAttentionRedaction(t *testing.T) {
	dir := trustScopeTestDirectory(t)
	owner, other := principal(t, "status-owner"), principal(t, "foreign-owner")
	grants := []Enrollment{enrollment(owner, "owned-status"), enrollment(other, "foreign-status")}
	for i := range grants {
		grants[i].TrustScope = TrustScopeDesktop
	}
	credential := strings.Repeat("private-credential", 3)
	host := session.ProcessIdentity{PID: 20, UID: uint32(os.Getuid()), Executable: "/private/process-secret/native-host", StartToken: "1790000000:1"}
	parent := session.ProcessIdentity{PID: 10, UID: uint32(os.Getuid()), Executable: "/private/process-secret/Chrome", StartToken: "1790000000:2"}
	var invalid atomic.Bool
	check := func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		return nativepeer.ChromeProcessEvidence{NativeHost: host, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, KernelPeerQualified: !invalid.Load()}, nil
	}
	credentials := map[string]string{}
	for _, g := range grants {
		credentials[channelKey(g.ProfileChannel, g.BrowserInstance)] = credential
	}
	b, err := newBrokerWithPeer(Config{SocketPath: filepath.Join(dir, "status.sock"), Grants: grants}, credentials, check)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	g, _ := NewGateway(b, GatewayOptions{})
	conn, err := net.Dial("unix", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	grant := grants[0]
	WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "profileChannel": grant.ProfileChannel, "browserInstance": grant.BrowserInstance, "extensionOrigin": grant.ExtensionOrigin, "credential": credential, "trustScope": TrustScopeDesktop})
	raw, err := ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var ack map[string]any
	json.Unmarshal(raw, &ack)
	WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": ack["executorChallenge"]})
	WriteFrame(conn, map[string]any{"type": "documents", "documents": []Document{{Identity: Identity{ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, TabID: 7, FrameID: 0, DocumentID: "private-document", Generation: 1}, Origin: grant.Origins[0], Title: "private-page-title"}}})
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.inventoryComplete })
	ctx := auth.WithPrincipal(context.Background(), owner)
	b.mu.Lock()
	c.pending["private-request"] = &pending{done: make(chan Reply, 1)}
	c.unknown["private-attempt"] = true
	b.mu.Unlock()
	status, err := g.BrowserStatus(ctx, owner)
	if err != nil || !status.Available || len(status.Channels) != 1 {
		t.Fatalf("owned status: %+v %v", status, err)
	}
	s := status.Channels[0]
	if !s.Connected || !s.ProcessQualified || !s.ScopeQualified || s.ProfileQualified || !s.ExecutorQualified || !s.InventoryComplete || s.DocumentCount != 1 || s.PendingCount != 1 || s.UnknownCount != 1 {
		t.Fatalf("independent channel stages/counts lost: %+v", s)
	}
	encoded, _ := json.Marshal(status)
	for _, private := range []string{"private", "credential", "documentId", "extensionOrigin", "profileChannel", "browserInstance", "https://", "Title", "Evidence"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("status leaked %s: %s", private, encoded)
		}
	}
	foreign, err := g.BrowserStatus(auth.WithPrincipal(context.Background(), other), other)
	if err != nil || len(foreign.Channels) != 1 || foreign.Channels[0].Connected || foreign.Channels[0].DocumentCount != 0 {
		t.Fatalf("foreign namespace saw owner channel: %+v %v", foreign, err)
	}
	if _, err = g.BrowserStatus(context.Background(), owner); err == nil {
		t.Fatal("unauthenticated diagnostic admitted")
	}
	if _, err = g.BrowserStatus(ctx, other); err == nil {
		t.Fatal("principal override diagnostic admitted")
	}
	for _, code := range []string{"storedFenceMismatch", "inventoryUnavailable", "inventoryIncomplete", "executorInjectionFailed", "executorBindingFailed", "executorNotQuiescent", "private-code-credential-secret"} {
		WriteFrame(conn, map[string]any{"type": "attention", "error": map[string]any{"code": code, "message": "private-message-credential-secret", "origin": "https://private.example"}})
		want := browserAttentionCode(code)
		waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.attentionCode == want })
		result, err := g.BrowserStatus(ctx, owner)
		if err != nil {
			t.Fatal(err)
		}
		row := result.Channels[0]
		if row.AttentionCode != want || row.ExecutorQualified || row.InventoryComplete || row.DocumentCount != 0 || row.PendingCount != 1 || row.UnknownCount != 1 {
			t.Fatalf("attention state/reconciliation barriers changed: %+v", row)
		}
		payload, _ := json.Marshal(result)
		if strings.Contains(string(payload), "private") {
			t.Fatalf("attention echoed payload: %s", payload)
		}
	}
	// Fresh failed process diagnostics must report unqualified without closing or sending input.
	invalid.Store(true)
	result, err := g.BrowserStatus(ctx, owner)
	if err != nil || !result.Channels[0].Connected || result.Channels[0].ProcessQualified || result.Channels[0].ScopeQualified {
		t.Fatalf("stale process status: %+v %v", result, err)
	}
	b.mu.Lock()
	connected := c.conn != nil
	delete(c.pending, "private-request")
	delete(c.unknown, "private-attempt")
	b.mu.Unlock()
	if !connected {
		t.Fatal("read-only status revoked connection")
	}
	invalid.Store(false)
	WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": ack["executorChallenge"]})
	waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.attentionCode == "" && c.executorQualified })
	result, err = g.BrowserStatus(ctx, owner)
	if err != nil || result.Channels[0].AttentionCode != "" || !result.Channels[0].ExecutorQualified {
		t.Fatalf("confirmed preparation did not clear attention: %+v %v", result, err)
	}
	conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err = ReadFrame(conn); err == nil {
		t.Fatal("status diagnostic sent a browser command")
	}
}
