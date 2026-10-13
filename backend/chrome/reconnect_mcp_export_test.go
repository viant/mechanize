package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
)

// Test-only trust adapter. The actual worker, Unix broker reader, ownership
// projection and MCP serializer execute unchanged; no installed browser is used.
func ReconnectMCPFixtureForTest(t *testing.T) (*Gateway, auth.Principal) {
	return reconnectMCPFixture(t, false)
}
func RolloverMCPFixtureForTest(t *testing.T) (*Gateway, auth.Principal) {
	return reconnectMCPFixture(t, true)
}
func reconnectMCPFixture(t *testing.T, success bool) (*Gateway, auth.Principal) {
	t.Helper()
	p := principal(t, "reconnect-mcp")
	grant := enrollment(p, "p1")
	grant.BrowserInstance = "b1"
	grant.Origins = []string{"https://fixture.test"}
	grant.TrustScope = TrustScopeDesktop
	host := session.ProcessIdentity{PID: 20, UID: uint32(os.Getuid()), Executable: "/fixture/native", StartToken: "host"}
	parent := session.ProcessIdentity{PID: 10, UID: uint32(os.Getuid()), Executable: "/fixture/chrome", StartToken: "browser"}
	check := func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		return nativepeer.ChromeProcessEvidence{NativeHost: host, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, KernelPeerQualified: true}, nil
	}
	b, err := newBrokerWithPeer(Config{SocketPath: filepath.Join(trustScopeTestDirectory(t), "reconnect.sock"), Grants: []Enrollment{grant}}, map[string]string{channelKey("p1", "b1"): "fixture-credential-012345678901234567890123456789"}, check)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	conn, err := net.Dial("unix", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "workerBuild": 32, "profileChannel": "p1", "browserInstance": "b1", "extensionOrigin": grant.ExtensionOrigin, "credential": "fixture-credential-012345678901234567890123456789", "trustScope": TrustScopeDesktop})
	raw, err := ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var command map[string]any
	if json.Unmarshal(raw, &command) != nil {
		t.Fatal("invalid qualification")
	}
	commands := []map[string]any{command}
	if success {
		conn.Close()
		waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.channels[channelKey("p1", "b1")].conn == nil })
		b.Close()
		b, err = newBrokerWithPeer(Config{SocketPath: filepath.Join(trustScopeTestDirectory(t), "restarted.sock"), Grants: []Enrollment{grant}}, map[string]string{channelKey("p1", "b1"): "fixture-credential-012345678901234567890123456789"}, check)
		if err != nil {
			t.Fatal(err)
		}
		conn, err = net.Dial("unix", b.listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "workerBuild": 32, "profileChannel": "p1", "browserInstance": "b1", "extensionOrigin": grant.ExtensionOrigin, "credential": "fixture-credential-012345678901234567890123456789", "trustScope": TrustScopeDesktop})
		raw, err = ReadFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		var next map[string]any
		if json.Unmarshal(raw, &next) != nil {
			t.Fatal("restart qualification unavailable")
		}
		commands = append(commands, next)
	}
	input, _ := json.Marshal(map[string]any{"commands": commands, "success": success})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "node", "testdata/worker_reconnect_attention.cjs")
	child.Stdin = bytes.NewReader(input)
	child.Stderr = os.Stderr
	frame, err := child.Output()
	if err != nil {
		t.Fatalf("actual worker diagnostic failed: %v", err)
	}
	var output struct {
		Frames       []json.RawMessage `json:"frames"`
		Preserved    bool              `json:"preserved"`
		HistoryCount int               `json:"historyCount"`
	}
	if json.Unmarshal(frame, &output) != nil || success && (!output.Preserved || output.HistoryCount != 1) {
		t.Fatal("worker archive proof unavailable")
	}
	for _, item := range output.Frames {
		var payload any
		if json.Unmarshal(item, &payload) != nil {
			t.Fatal("worker frame unavailable")
		}
		if err = WriteFrame(conn, payload); err != nil {
			t.Fatal(err)
		}
	}
	waitControl(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		c := b.channels[channelKey("p1", "b1")]
		if success {
			return c.executorQualified && c.inventoryComplete
		}
		return c.reconnectJournal != nil
	})
	g, err := NewGateway(b, GatewayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return g, p
}
