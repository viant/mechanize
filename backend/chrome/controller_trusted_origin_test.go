package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
)

func TestTrustedControllerOriginRetainsSessionBoundsAndToolConsent(t *testing.T) {
	p, err := auth.NewPrincipal("fixture-issuer", "", "trusted-controller", []string{"desktop:observe", "desktop:control", "consent:admin"})
	if err != nil {
		t.Fatal(err)
	}
	grant := enrollment(p, "trusted-controller")
	b := fixtureBroker(t, grant)
	dispatcher := &controllerDispatchFixture{closed: make(chan struct{}, 1)}
	dispatcher.call = func(ctx context.Context, id ControllerIdentity, _ ControllerToolCall) (*schema.CallToolResult, error) {
		if auth.NativeHuman(ctx) {
			t.Error("connection minted human authority")
		}
		if _, ok := auth.ConsentBindingFromContext(ctx); ok {
			t.Error("connection minted tool consent")
		}
		if id.Principal.ClientID == p.ClientID || id.DocumentID != "document" {
			t.Error("document actor was not isolated")
		}
		// The ordinary tool consent decision is still authoritative.
		return nil, errors.New("tool consent required PRIVATE-CANARY")
	}
	b.controllerDispatcher = dispatcher
	conn := connectHost(t, b, grant)
	b.mu.Lock()
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test"}}
	b.mu.Unlock()
	open := map[string]any{"type": "controllerOpen", "sessionId": "trusted", "documentId": "document", "tabId": 7, "origin": "https://shell.fixture.test", "brokerEpoch": b.epoch, "channelEpoch": c.epoch, "scopeHash": c.scopeHash}
	if err := WriteFrame(conn, open); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	raw, err := ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var ack map[string]any
	json.Unmarshal(raw, &ack)
	if ack["type"] != "controllerApproval" {
		t.Fatal("trusted origin required another approval")
	}
	b.mu.Lock()
	original := c.controllerSessions["trusted"]
	expiry := original.ExpiresAt
	b.mu.Unlock()
	if expiry.After(time.Now().Add(controllerIdleTTL)) || !original.Approved {
		t.Fatal("unbounded admission")
	}
	ctx := auth.WithPrincipal(context.Background(), p)
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGateway(b, GatewayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.ManageControllers(human, p, ControllerManagement{ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, Action: "configure", Policy: &ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadFrame(conn); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	same := c.controllerSessions["trusted"] == original && original.ExpiresAt.Equal(expiry)
	b.mu.Unlock()
	if !same {
		t.Fatal("identical save renewed or replaced session")
	}
	request := map[string]any{"type": "controllerRequest", "requestId": "tool-call", "operation": "tools/call", "params": map[string]any{"name": "mechanize_observe", "arguments": map[string]any{}}, "deadlineUnixMs": time.Now().Add(time.Second).UnixMilli(), "sessionId": "trusted", "documentId": "document", "origin": "https://shell.fixture.test", "brokerEpoch": b.epoch, "channelEpoch": c.epoch, "scopeHash": c.scopeHash}
	WriteFrame(conn, request)
	raw, err = ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	json.Unmarshal(raw, &result)
	if result["error"] != "unavailable" || dispatcher.calls.Load() != 1 {
		t.Fatal("tool consent refusal was bypassed")
	}
	if _, err = g.ManageControllers(human, p, ControllerManagement{ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, Action: "configure", Policy: &ControllerPolicy{Enabled: false, Origins: []string{}}}); err != nil {
		t.Fatal(err)
	}
	ReadFrame(conn)
	request["requestId"] = "after-disable"
	WriteFrame(conn, request)
	raw, err = ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	result = nil
	json.Unmarshal(raw, &result)
	if result["error"] != "unavailable" || dispatcher.calls.Load() != 1 {
		t.Fatal("disabled policy dispatched tool")
	}
}

func TestTrustedControllerOriginRefusesForeignOrUnqualifiedOpen(t *testing.T) {
	for _, mode := range []string{"disabled", "origin", "fence", "document", "extra", "scope"} {
		t.Run(mode, func(t *testing.T) {
			grant := enrollment(principal(t, "controller-negative"), "controller-negative")
			b := fixtureBroker(t, grant)
			conn := connectHost(t, b, grant)
			b.mu.Lock()
			c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
			c.controllerPolicy = ControllerPolicy{Enabled: mode != "disabled", Origins: []string{"https://shell.fixture.test"}}
			if mode == "scope" {
				c.scopeQualified = false
				c.fixtureOnly = false
			}
			b.mu.Unlock()
			open := map[string]any{"type": "controllerOpen", "sessionId": "session", "documentId": "document", "tabId": 7, "origin": "https://shell.fixture.test", "brokerEpoch": b.epoch, "channelEpoch": c.epoch, "scopeHash": c.scopeHash}
			switch mode {
			case "origin":
				open["origin"] = "https://other.fixture.test"
			case "fence":
				open["brokerEpoch"] = "foreign"
			case "document":
				open["documentId"] = ""
			case "extra":
				open["frameId"] = 1
			}
			raw, _ := json.Marshal(open)
			b.controllerLifecycle(c, conn, raw)
			b.mu.Lock()
			count := len(c.controllerSessions)
			b.mu.Unlock()
			if count != 0 {
				t.Fatal("unqualified origin/session admitted")
			}
		})
	}
}
