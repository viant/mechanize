package chrome

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
)

type controllerInitializeFixture struct {
	controllerDispatchFixture
	initialized atomic.Int32
}

func (f *controllerInitializeFixture) Initialize(ctx context.Context, identity ControllerIdentity) (*schema.InitializeResult, error) {
	principal, err := auth.FromContext(ctx)
	if err != nil || principal.ClientID != identity.Principal.ClientID || identity.DocumentID != "controller-document" {
		return nil, auth.ErrUnauthorized
	}
	f.initialized.Add(1)
	var result schema.InitializeResult
	err = json.Unmarshal([]byte(`{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"mechanize","version":"fixture"}}`), &result)
	return &result, err
}

// Exercise the shipped browser bridge and real native decoder/MCP dispatcher.
// initialize metadata stays at the browser boundary; forwarding it as params
// would violate the deliberately closed controllerRequest native schema.
func TestControllerInitializeActualExtensionRoundTrip(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required for actual controller fixture")
	}
	grant := enrollment(principal(t, "controller-initialize"), "controller-initialize-channel")
	broker := fixtureBroker(t, grant)
	dispatcher := &controllerInitializeFixture{controllerDispatchFixture: controllerDispatchFixture{closed: make(chan struct{}, 1)}}
	broker.controllerDispatcher = dispatcher
	conn := connectHost(t, broker, grant)
	publish(t, broker, conn, grant, document(grant, 7))
	broker.mu.Lock()
	channel := broker.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	// Controller metadata remains usable after renderer readiness is withdrawn.
	channel.executorQualified = false
	channel.inventoryComplete = false
	channel.documents = nil
	binding := map[string]string{"brokerEpoch": broker.epoch, "channelEpoch": channel.epoch, "scopeHash": channel.scopeHash}
	channel.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test"}}
	broker.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, node, "../../extension/chrome/test/controller-roundtrip.cjs")
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		input.Close()
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	})
	encoder, scanner := json.NewEncoder(input), bufio.NewScanner(output)
	if err = encoder.Encode(binding); err != nil {
		t.Fatal(err)
	}
	if !scanner.Scan() {
		t.Fatal("extension open frame missing")
	}
	var open struct {
		Type, SessionID, Origin, DocumentID string
		TabID                               int
	}
	if json.Unmarshal(scanner.Bytes(), &open) != nil || open.Type != "controllerOpen" || open.SessionID == "" {
		t.Fatal("closed extension open frame invalid")
	}
	if err = WriteFrame(conn, json.RawMessage(scanner.Bytes())); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	approval, err := ReadFrame(conn)
	if err != nil {
		t.Fatal("automatic policy admission missing", err)
	}
	broker.mu.Lock()
	session := channel.controllerSessions[open.SessionID]
	broker.mu.Unlock()
	if session == nil || !session.Approved {
		t.Fatal("trusted page session was not admitted")
	}
	if err = encoder.Encode(json.RawMessage(approval)); err != nil {
		t.Fatal(err)
	}
	if !scanner.Scan() {
		t.Fatal("extension initialize frame missing")
	}
	request, handled := decodeControllerRequest(scanner.Bytes(), time.Now())
	if !handled || request == nil || request.Operation != "initialize" || request.Params != nil || request.SessionID != session.ID {
		t.Fatal("actual extension initialization did not match native schema")
	}
	if err = WriteFrame(conn, request); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	raw, err := ReadFrame(conn)
	if err != nil {
		t.Fatal("native initialization response missing", err)
	}
	if err = encoder.Encode(json.RawMessage(raw)); err != nil {
		t.Fatal(err)
	}
	if !scanner.Scan() {
		t.Fatal("browser initialization result missing")
	}
	var result struct {
		Type  string
		Value struct {
			Type, RequestID, Error string
			Result                 schema.InitializeResult
		}
	}
	if json.Unmarshal(scanner.Bytes(), &result) != nil || result.Type != "fixtureBrowserResult" || result.Value.Type != "result" || result.Value.RequestID != "browser-initialize" || result.Value.Error != "" || result.Value.Result.ServerInfo.Name != "mechanize" || dispatcher.initialized.Load() != 1 {
		t.Fatal("browser initialization result failed projection or correlation")
	}
	if err = child.Wait(); err != nil {
		t.Fatal("controller fixture failed", err)
	}
}
