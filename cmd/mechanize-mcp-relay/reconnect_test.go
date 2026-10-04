package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/jsonrpc"
	"github.com/viant/jsonrpc/transport/client/http/streamable"
)

type reconnectBroker struct {
	generation      atomic.Int64
	initializations atomic.Int64
	mutations       atomic.Int64
	requests        atomic.Int64
}

func (b *reconnectBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session := "fixture-session-" + strconv.FormatInt(b.generation.Load(), 10)
	if r.Method == http.MethodGet {
		if r.Header.Get("Mcp-Session-Id") != session {
			http.Error(w, "expired fixture session", 404)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return
	}
	var req jsonrpc.Request
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid", 400)
		return
	}
	if req.Method == "initialize" {
		b.initializations.Add(1)
		w.Header().Set("Mcp-Session-Id", session)
	} else if r.Header.Get("Mcp-Session-Id") != session {
		// Include a matching RPC error to prove a session 404 cannot be mistaken
		// for an ordinary method error and leave the expired client cached.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(&jsonrpc.Response{Id: req.Id, Jsonrpc: "2.0", Error: jsonrpc.NewError(-32000, "fixture session expired", nil)})
		return
	}
	if req.Id == nil {
		w.WriteHeader(202)
		return
	}
	if req.Method == "tools/call" {
		b.requests.Add(1)
		var p struct {
			Name string `json:"name"`
		}
		json.Unmarshal(req.Params, &p)
		if p.Name == "fixture_mutation_lost_reply" {
			b.mutations.Add(1)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	result := json.RawMessage(`{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}`)
	if req.Method != "initialize" {
		result = json.RawMessage(`{"fixture":"healthy"}`)
	}
	json.NewEncoder(w).Encode(&jsonrpc.Response{Id: req.Id, Jsonrpc: "2.0", Result: result})
}
func liveReconnectFixture(t *testing.T) (*recoveringTransport, *reconnectBroker) {
	t.Helper()
	b := &reconnectBroker{}
	b.generation.Store(1)
	server := httptest.NewServer(b)
	t.Cleanup(server.Close)
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	t.Cleanup(base.CloseIdleConnections)
	httpClient := &http.Client{Transport: &secureTransport{endpoint: server.URL + "/mcp", loadCredential: func(context.Context) (string, error) { return strings.Repeat("fixture", 8), nil }, base: base}, Timeout: 3 * time.Second}
	create := func(owner context.Context) (connection, error) {
		return streamable.New(owner, server.URL+"/mcp", streamable.WithHTTPClient(httpClient), streamable.WithProtocolVersion(protocol), streamable.WithRequestHeaderProvider(headers), streamable.WithRunTimeout(0))
	}
	initial, err := create(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	manager := newRecoveringTransport(context.Background(), initial, create)
	t.Cleanup(func() { manager.Close() })
	return manager, b
}
func initializeRelay(t *testing.T, r *recoveringTransport) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := r.Send(ctx, &jsonrpc.Request{Id: 1, Jsonrpc: "2.0", Method: "initialize", Params: json.RawMessage(`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}`)})
	if err != nil || res == nil || res.Error != nil {
		t.Fatal("fixture initialization failed")
	}
	if err = r.Notify(ctx, &jsonrpc.Notification{Jsonrpc: "2.0", Method: "notifications/initialized", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
}
func relayCall(id int, name string) *jsonrpc.Request {
	p, _ := json.Marshal(map[string]any{"name": name, "arguments": map[string]any{}})
	return &jsonrpc.Request{Id: id, Jsonrpc: "2.0", Method: "tools/call", Params: p}
}
func TestRelayNextCallReinitializesAfterBrokerSessionRestart(t *testing.T) {
	r, b := liveReconnectFixture(t)
	initializeRelay(t, r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.Send(ctx, relayCall(2, "mechanize_capabilities")); err != nil {
		t.Fatal(err)
	}
	b.generation.Store(2)
	if _, err := r.Send(ctx, relayCall(3, "mechanize_capabilities")); err == nil {
		t.Fatal("expired session was retained as an ordinary RPC response")
	}
	if b.initializations.Load() != 1 || b.requests.Load() != 1 {
		t.Fatal("failed call was transparently reinitialized or replayed")
	}
	res, err := r.Send(ctx, relayCall(4, "mechanize_capabilities"))
	if err != nil || res == nil || res.Error != nil {
		t.Fatal("next distinct call did not recover", err)
	}
	if b.initializations.Load() != 2 || b.requests.Load() != 2 {
		t.Fatal("recovery replayed operations or failed to initialize new session")
	}
}
func TestRelayLostMutationReplyIsNeverReplayedDuringRecovery(t *testing.T) {
	r, b := liveReconnectFixture(t)
	initializeRelay(t, r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.Send(ctx, relayCall(2, "fixture_mutation_lost_reply")); err == nil {
		t.Fatal("lost mutation response treated as success")
	}
	if b.mutations.Load() != 1 || b.initializations.Load() != 1 {
		t.Fatal("uncertain mutation retried or handshake repeated in same call")
	}
	if _, err := r.Send(ctx, relayCall(3, "mechanize_capabilities")); err != nil {
		t.Fatal("subsequent read failed to recover", err)
	}
	if b.mutations.Load() != 1 || b.initializations.Load() != 2 {
		t.Fatal("uncertain mutation replayed by new connection")
	}
}

func TestProtocolReconnectFailureUsesSentinelWithoutResendingOperation(t *testing.T) {
	var mutationCalls atomic.Int32
	initial := &closedFake{fakeTransport: &fakeTransport{send: func(_ context.Context, req *jsonrpc.Request) (*jsonrpc.Response, error) {
		if req.Method == "initialize" {
			return &jsonrpc.Response{Id: req.Id, Jsonrpc: "2.0", Result: json.RawMessage(`{}`)}, nil
		}
		if req.Method == "tools/call" {
			mutationCalls.Add(1)
		}
		return nil, errors.New("PRIVATE_TOOL_TRANSPORT_DETAIL")
	}}}
	var reconnectCalls atomic.Int32
	failedReconnect := &closedFake{fakeTransport: &fakeTransport{send: func(_ context.Context, _ *jsonrpc.Request) (*jsonrpc.Response, error) {
		reconnectCalls.Add(1)
		return nil, errors.New("PRIVATE_PROTOCOL_RECONNECT_DETAIL")
	}}}
	manager := newRecoveringTransport(context.Background(), initial, func(context.Context) (connection, error) {
		return failedReconnect, nil
	})
	defer manager.Close()
	initializeRelay(t, manager)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := manager.Send(ctx, relayCall(2, "fixture_mutation_once")); err == nil {
		t.Fatal("lost mutation reply treated as success")
	}
	_, err := manager.Send(ctx, relayCall(3, "subsequent_read"))
	if !errors.Is(err, errMCPProtocolReconnect) || strings.Contains(err.Error(), "PRIVATE_") {
		t.Fatal("protocol reconnection failure was not safely classified")
	}
	if mutationCalls.Load() != 1 || reconnectCalls.Load() != 1 {
		t.Fatal("mutation was replayed during protocol reconnection", mutationCalls.Load(), reconnectCalls.Load())
	}
}

type closedFake struct {
	*fakeTransport
	closes atomic.Int32
}

func (f *closedFake) Close() error { f.closes.Add(1); return nil }
func TestRelayLateOldConnectionFailureCannotCloseRecoveredPeer(t *testing.T) {
	lateStarted := make(chan struct{})
	releaseLate := make(chan struct{})
	defer close(releaseLate)
	old := &closedFake{fakeTransport: &fakeTransport{send: func(ctx context.Context, req *jsonrpc.Request) (*jsonrpc.Response, error) {
		if req.Id == "late" {
			close(lateStarted)
			select {
			case <-releaseLate:
			case <-ctx.Done():
			}
			return nil, errors.New("fixture failure")
		}
		return nil, errors.New("fixture failure")
	}}}
	fresh := &closedFake{fakeTransport: &fakeTransport{send: func(_ context.Context, req *jsonrpc.Request) (*jsonrpc.Response, error) {
		return &jsonrpc.Response{Id: req.Id, Jsonrpc: "2.0", Result: json.RawMessage(`{}`)}, nil
	}}}
	var creates atomic.Int32
	manager := newRecoveringTransport(context.Background(), old, func(context.Context) (connection, error) { creates.Add(1); return fresh, nil })
	defer manager.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	late := make(chan error, 1)
	go func() { _, err := manager.Send(ctx, &jsonrpc.Request{Id: "late", Method: "tools/list"}); late <- err }()
	<-lateStarted
	if _, err := manager.Send(ctx, &jsonrpc.Request{Id: "fail", Method: "tools/list"}); err == nil {
		t.Fatal("fixture failed connection unexpectedly succeeded")
	}
	if _, err := manager.Send(ctx, &jsonrpc.Request{Id: "fresh", Method: "tools/list"}); err != nil {
		t.Fatal(err)
	}
	// Cancel the old request to deliver its error after the new peer is ready.
	cancel()
	select {
	case <-late:
	case <-time.After(time.Second):
		t.Fatal("old call did not settle")
	}
	if fresh.closes.Load() != 0 || creates.Load() != 1 {
		t.Fatal("late error invalidated a newer connection")
	}
	if _, err := manager.Send(context.Background(), &jsonrpc.Request{Id: "again", Method: "tools/list"}); err != nil || creates.Load() != 1 {
		t.Fatal("healthy recovered peer was replaced")
	}
}
