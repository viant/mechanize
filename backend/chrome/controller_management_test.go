package chrome

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

func TestControllerNativeManagementAndTrustedOriginAdmission(t *testing.T) {
	p, err := auth.NewPrincipal("fixture-issuer", "", "controller-native", []string{"desktop:observe", "consent:admin"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), p)
	native, err := auth.WithNativeHuman(ctx)
	if err != nil {
		t.Fatal(err)
	}
	grant := enrollment(p, "native-controller")
	b := fixtureBroker(t, grant)
	g, err := NewGateway(b, GatewayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	conn := connectHost(t, b, grant)
	input := ControllerManagement{ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, Action: "configure", Policy: &ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test"}}}
	if _, err = g.ManageControllers(ctx, p, input); err == nil {
		t.Fatal("non-native human configured controllers")
	}
	if _, err = g.ManageControllers(native, p, input); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	raw, err := ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	json.Unmarshal(raw, &policy)
	if policy["type"] != "controllerPolicy" {
		t.Fatal(string(raw))
	}
	open := map[string]any{"type": "controllerOpen", "sessionId": "session1", "documentId": "document1", "tabId": 7, "origin": "https://shell.fixture.test", "brokerEpoch": policy["brokerEpoch"], "channelEpoch": policy["channelEpoch"], "scopeHash": policy["scopeHash"]}
	if err = WriteFrame(conn, open); err != nil {
		t.Fatal(err)
	}
	if raw, err = ReadFrame(conn); err != nil {
		t.Fatal(err)
	}
	var approval map[string]any
	if json.Unmarshal(raw, &approval) != nil || approval["type"] != "controllerApproval" || approval["sessionId"] != "session1" {
		t.Fatal("trusted origin did not auto-connect")
	}
	input.Action = "status"
	input.Policy = nil
	var state ControllerState
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		state, err = g.ManageControllers(native, p, input)
		if err != nil {
			t.Fatal(err)
		}
		if len(state.Sessions) == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(state.Sessions) != 1 || !state.Sessions[0].Approved {
		t.Fatalf("unexpected sessions %+v", state)
	}
	req := map[string]any{"type": "controllerRequest", "requestId": "request1", "operation": "connection.status", "deadlineUnixMs": time.Now().Add(time.Second).UnixMilli(), "sessionId": "session1", "documentId": "document1", "origin": "https://shell.fixture.test", "brokerEpoch": policy["brokerEpoch"], "channelEpoch": policy["channelEpoch"], "scopeHash": policy["scopeHash"]}
	WriteFrame(conn, req)
	raw, err = ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	json.Unmarshal(raw, &result)
	if _, ok := result["ready"].(bool); !ok || result["error"] != nil {
		t.Fatal("trusted connection metadata refused")
	}
	input.Action = "approve"
	input.SessionID = "session1"
	if _, err = g.ManageControllers(ctx, p, input); err == nil {
		t.Fatal("page received native-human management authority")
	}
	req["requestId"] = "request2"
	req["operation"] = "tools.list"
	WriteFrame(conn, req)
	raw, err = ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	result = nil
	json.Unmarshal(raw, &result)
	if result["tools"] == nil || len(result) != 3 {
		t.Fatal(string(raw))
	}
	input.Action = "revoke"
	if _, err = g.ManageControllers(native, p, input); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadFrame(conn); err != nil {
		t.Fatal(err)
	}
	req["requestId"] = "request3"
	WriteFrame(conn, req)
	raw, err = ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	result = nil
	json.Unmarshal(raw, &result)
	if result["error"] != "unavailable" {
		t.Fatal("revoked call accepted")
	}
}

func TestControllerLocalhostPortPatternsMatchOnlyConcreteExactHost(t *testing.T) {
	for _, pattern := range []string{"localhost:*", "http://localhost:*", "https://localhost:*"} {
		if !ValidControllerPolicy(ControllerPolicy{Enabled: true, Origins: []string{pattern}}) {
			t.Fatal("closed pattern rejected", pattern)
		}
		for _, origin := range []string{"http://localhost", "https://localhost", "http://localhost:3000", "https://localhost:65535"} {
			expected := pattern == "localhost:*" || strings.HasPrefix(origin, strings.Split(pattern, "://")[0]+"://")
			if controllerPolicyMatches([]string{pattern}, origin) != expected {
				t.Fatal("scheme/port matcher drift", pattern, origin)
			}
		}
		for _, origin := range []string{"http://127.0.0.1:3000", "http://localhost.evil:3000", "https://evil.localhost:3000", "http://localhost.:3000", "http://user@localhost:3000", "http://localhost:3000/path", "http://localhost:3000?q=x", "http://localhost:3000#x", "http://localhost:", "http://localhost:0", "http://localhost:65536", "http://localhost:03000", "http://localhost:*", "localhost:*"} {
			if controllerPolicyMatches([]string{pattern}, origin) {
				t.Fatal("unsafe origin matched", origin)
			}
		}
	}
	for _, bad := range []string{"*", "*.localhost:*", "localhost:*:3000", "localhost:*/path", "http://localhost:*/", "https://user@localhost:*", "https://localhost:*?x=1", "https://localhost:*#x", "https://localhost.evil:*", "http://127.0.0.1:*"} {
		if ValidControllerPolicy(ControllerPolicy{Enabled: true, Origins: []string{bad}}) {
			t.Fatal("invalid pattern admitted", bad)
		}
	}
}

func TestControllerWildcardPolicyDoesNotTransferDocumentSessionToAnotherOrigin(t *testing.T) {
	p := principal(t, "wildcard-document")
	grant := enrollment(p, "wildcard-profile")
	b := fixtureBroker(t, grant)
	conn := connectHost(t, b, grant)
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"localhost:*"}}
	c.controllerSessions["session"] = &ControllerSession{ID: "session", Origin: "http://localhost:3000", DocumentID: "document", Approved: true, ExpiresAt: time.Now().Add(time.Minute)}
	request := &controllerRequest{Origin: "http://localhost:3000", DocumentID: "document", SessionID: "session", BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, Deadline: time.Now().Add(time.Second).UnixMilli()}
	if !b.controllerRequestAllowedLocked(c, c.conn, request) {
		t.Fatal("matching session denied")
	}
	for _, origin := range []string{"http://localhost:3001", "https://localhost:3000", "http://localhost.evil:3000", "localhost:*"} {
		request.Origin = origin
		if b.controllerRequestAllowedLocked(c, c.conn, request) {
			t.Fatal("forged request borrowed session")
		}
	}
	request.Origin = "http://localhost:3000"
	c.controllerPolicy.Origins = []string{"https://fixture.test"}
	if b.controllerRequestAllowedLocked(c, c.conn, request) {
		t.Fatal("removed origin retained authority")
	}
	_ = conn
}
