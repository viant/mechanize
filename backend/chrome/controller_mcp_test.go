package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
)

type controllerDispatchFixture struct {
	call   func(context.Context, ControllerIdentity, ControllerToolCall) (*schema.CallToolResult, error)
	closed chan struct{}
	calls  atomic.Int32
}

func (f *controllerDispatchFixture) Initialize(context.Context, ControllerIdentity) (*schema.InitializeResult, error) {
	return &schema.InitializeResult{}, nil
}
func (f *controllerDispatchFixture) ListTools(context.Context, ControllerIdentity) (*schema.ListToolsResult, error) {
	return &schema.ListToolsResult{}, nil
}
func (f *controllerDispatchFixture) CallTool(ctx context.Context, id ControllerIdentity, c ControllerToolCall) (*schema.CallToolResult, error) {
	f.calls.Add(1)
	return f.call(ctx, id, c)
}
func (f *controllerDispatchFixture) CloseController(context.Context, ControllerIdentity) error {
	select {
	case f.closed <- struct{}{}:
	default:
	}
	return nil
}
func TestControllerMCPKeepsBrowserReaderLiveAndCancelsOnDisconnect(t *testing.T) {
	grant := enrollment(principal(t, "reverse"), "reverse-channel")
	b := fixtureBroker(t, grant)
	fixture := &controllerDispatchFixture{closed: make(chan struct{}, 1)}
	b.controllerDispatcher = fixture
	conn := connectHost(t, b, grant)
	doc := document(grant, 7)
	publish(t, b, conn, grant, doc)
	b.mu.Lock()
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test"}}
	s := &ControllerSession{ID: "session1", Origin: "https://shell.fixture.test", DocumentID: "controller-doc", Approved: true, ExpiresAt: time.Now().Add(time.Minute)}
	c.controllerSessions[s.ID] = s
	b.initControllerSessionLocked(c, s)
	req := controllerRequest{Type: "controllerRequest", RequestID: "reverse1", Operation: "tools/call", Params: &ControllerToolCall{Name: "mechanize_observe", Arguments: json.RawMessage(`{}`)}, Origin: s.Origin, DocumentID: s.DocumentID, SessionID: s.ID, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, Deadline: time.Now().Add(3 * time.Second).UnixMilli()}
	b.mu.Unlock()
	fixture.call = func(ctx context.Context, id ControllerIdentity, _ ControllerToolCall) (*schema.CallToolResult, error) {
		p, err := auth.FromContext(ctx)
		if err != nil || p.ClientID == grant.Principal.ClientID || p.ClientID != id.Principal.ClientID || id.DocumentID != s.DocumentID || id.ConversationID != s.ID {
			return nil, errors.New("unbound controller actor")
		}
		if _, err = b.call(ctx, c, Command{Action: "observe", Identity: doc.Identity}, false); err != nil {
			return nil, err
		}
		return &schema.CallToolResult{StructuredContent: map[string]any{"observed": true}}, nil
	}
	if err := WriteFrame(conn, req); err != nil {
		t.Fatal(err)
	}
	cmd := nextCommand(t, conn)
	if cmd.Action != "observe" {
		t.Fatal("canonical browser call missing")
	}
	if err := WriteFrame(conn, Reply{RequestID: cmd.RequestID, Identity: cmd.Identity}); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	raw, err := ReadFrame(conn)
	if err != nil {
		t.Fatal("reader deadlocked", err)
	}
	var reply map[string]any
	json.Unmarshal(raw, &reply)
	if reply["result"] == nil {
		t.Fatal(string(raw))
	}
	begun := make(chan struct{})
	canceled := make(chan struct{})
	fixture.call = func(ctx context.Context, _ ControllerIdentity, _ ControllerToolCall) (*schema.CallToolResult, error) {
		close(begun)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}
	req.RequestID = "reverse2"
	if err = WriteFrame(conn, req); err != nil {
		t.Fatal(err)
	}
	select {
	case <-begun:
	case <-time.After(time.Second):
		t.Fatal("second call not started")
	}
	if err = WriteFrame(conn, map[string]any{"type": "controllerClosed", "sessionId": s.ID, "brokerEpoch": req.BrokerEpoch, "channelEpoch": req.ChannelEpoch, "scopeHash": req.ScopeHash}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("revocation did not cancel request")
	}
	select {
	case <-fixture.closed:
	case <-time.After(time.Second):
		t.Fatal("runtime cleanup not called")
	}
	req.RequestID = "reverse3"
	if err = WriteFrame(conn, req); err != nil {
		t.Fatal(err)
	}
	raw, err = ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	reply = nil
	json.Unmarshal(raw, &reply)
	if reply["error"] != "unavailable" || fixture.calls.Load() != 2 {
		t.Fatal("revoked request executed/replayed")
	}
}

func TestControllerMetadataWithoutExecutorRetainsCanonicalToolRefusal(t *testing.T) {
	grant := enrollment(principal(t, "metadata-only-controller"), "metadata-only-channel")
	b := fixtureBroker(t, grant)
	dispatcher := &controllerDispatchFixture{closed: make(chan struct{}, 1)}
	b.controllerDispatcher = dispatcher
	conn := connectHost(t, b, grant)
	b.mu.Lock()
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	c.executorQualified = false
	c.inventoryComplete = false
	c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test"}}
	s := &ControllerSession{ID: "metadata-session", Origin: "https://shell.fixture.test", DocumentID: "controller-document", Approved: true, ExpiresAt: time.Now().Add(time.Minute)}
	c.controllerSessions[s.ID] = s
	b.initControllerSessionLocked(c, s)
	req := controllerRequest{Type: "controllerRequest", Origin: s.Origin, DocumentID: s.DocumentID, SessionID: s.ID, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, Deadline: time.Now().Add(3 * time.Second).UnixMilli()}
	b.mu.Unlock()
	dispatcher.call = func(ctx context.Context, id ControllerIdentity, call ControllerToolCall) (*schema.CallToolResult, error) {
		if auth.NativeHuman(ctx) {
			t.Error("controller received native human authority")
		}
		_, err := b.call(ctx, c, Command{Action: "observe", Identity: document(grant, 7).Identity}, false)
		if err == nil {
			t.Error("missing executor admitted ordinary tool")
		}
		return nil, err
	}
	for index, operation := range []string{"initialize", "tools/list", "tools/call"} {
		req.RequestID = fmt.Sprintf("metadata-%d", index)
		req.Operation = operation
		if operation == "tools/call" {
			req.Params = &ControllerToolCall{Name: "mechanize_observe", Arguments: json.RawMessage(`{}`)}
		}
		if err := WriteFrame(conn, req); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		raw, err := ReadFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if json.Unmarshal(raw, &result) != nil || result["type"] != "controllerResult" || result["requestId"] != req.RequestID {
			t.Fatal("unexpected renderer dispatch or uncorrelated result")
		}
		if operation == "tools/call" {
			if result["error"] != "unavailable" {
				t.Fatal("canonical execution refusal disappeared")
			}
		} else if result["result"] == nil || result["error"] != nil {
			t.Fatal("metadata depended on executor", string(raw))
		}
	}
	if dispatcher.calls.Load() != 1 {
		t.Fatal("tool dispatch did not use original canonical adapter")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if c.executorQualified || c.inventoryComplete || len(c.pending) != 0 || len(c.unknown) != 0 || c.controllerSessions[s.ID] != s {
		t.Fatal("discovery changed executor or session authority")
	}
}
