package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/viant/mcp-protocol/schema"
	"testing"
	"time"
)

func TestControllerImageWithoutNegotiatedReceiverReturnsOneClosedFailure(t *testing.T) {
	grant := enrollment(principal(t, "controller-old-receiver"), "controller-old-receiver-channel")
	b := fixtureBroker(t, grant)
	pixels := controllerPNG(t)
	dispatcher := &controllerDispatchFixture{closed: make(chan struct{}, 1), call: func(context.Context, ControllerIdentity, ControllerToolCall) (*schema.CallToolResult, error) {
		return controllerImageAnswer(pixels), nil
	}}
	b.controllerDispatcher = dispatcher
	conn := connectHost(t, b, grant)
	publish(t, b, conn, grant, document(grant, 7))
	b.mu.Lock()
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test"}}
	s := &ControllerSession{ID: "owned-session", Origin: "https://shell.fixture.test", DocumentID: "controller-doc", Approved: true, ExpiresAt: time.Now().Add(time.Minute)}
	c.controllerSessions[s.ID] = s
	b.initControllerSessionLocked(c, s)
	request := controllerRequest{Type: "controllerRequest", RequestID: "original", Operation: "tools/call", Params: &ControllerToolCall{Name: "mechanize_capture", Arguments: json.RawMessage(`{}`)}, Origin: s.Origin, DocumentID: s.DocumentID, SessionID: s.ID, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, Deadline: time.Now().Add(3 * time.Second).UnixMilli()}
	b.mu.Unlock()
	if e := WriteFrame(conn, request); e != nil {
		t.Fatal(e)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	raw, e := ReadFrame(conn)
	if e != nil {
		t.Fatal(e)
	}
	var response map[string]any
	if json.Unmarshal(raw, &response) != nil || response["error"] != "resultTransferInvalid" || len(response) != 3 || dispatcher.calls.Load() != 1 || bytes.Contains(raw, []byte("data")) {
		t.Fatal("legacy receiver got image bytes or replay")
	}
}
