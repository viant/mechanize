package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/jsonrpc"
)

func TestCredentialPrivateReference(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	config := filepath.Join(dir, "config")
	token := strings.Repeat("fixture", 8)
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"stdioCredential": map[string]any{"URL": tokenPath}})
	if err := os.WriteFile(config, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := credential(context.Background(), config)
	if err != nil || got != token {
		t.Fatal("private Scy resolution failed", err)
	}
	if err := os.Chmod(tokenPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = credential(context.Background(), config); err == nil {
		t.Fatal("accepted public token")
	}
	if err = os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(config, tokenPath); err != nil {
		t.Fatal(err)
	}
	if _, err = credential(context.Background(), config); err == nil {
		t.Fatal("accepted token symlink")
	}
}
func TestEndpointBoundaries(t *testing.T) {
	for _, url := range []string{"https://127.0.0.1:4987/mcp", "http://example.com/mcp", "http://127.0.0.1/mcp?x=1", "http://a@127.0.0.1/mcp"} {
		if endpoint(url) == nil {
			t.Fatal("accepted", url)
		}
	}
	if err := endpoint("http://127.0.0.1:4987/mcp"); err != nil {
		t.Fatal(err)
	}
}

type fakeTransport struct {
	calls atomic.Int32
	send  func(context.Context, *jsonrpc.Request) (*jsonrpc.Response, error)
}

func (f *fakeTransport) Send(ctx context.Context, r *jsonrpc.Request) (*jsonrpc.Response, error) {
	f.calls.Add(1)
	return f.send(ctx, r)
}
func (f *fakeTransport) Notify(context.Context, *jsonrpc.Notification) error { return nil }
func TestErrorNotReplayedOrDisclosed(t *testing.T) {
	f := &fakeTransport{send: func(context.Context, *jsonrpc.Request) (*jsonrpc.Response, error) { return nil, errors.New("SECRET") }}
	p := &proxy{remote: f, active: map[string]context.CancelFunc{}}
	r := &jsonrpc.Request{Id: "opaque", Method: "tools/call", Jsonrpc: "2.0", Params: json.RawMessage(`{"name":"act","arguments":{}}`)}
	res := &jsonrpc.Response{Id: r.Id, Jsonrpc: r.Jsonrpc}
	p.Serve(context.Background(), r, res)
	if f.calls.Load() != 1 || res.Error == nil || strings.Contains(res.Error.Message, "SECRET") || res.Id != r.Id {
		t.Fatal("retry, disclosure, or ID loss")
	}
}

func TestTransportFailuresExposeOnlySafeCategoriesAndNeverReplay(t *testing.T) {
	privateError := "private transport URL https://private.invalid/mcp?token=PRIVATE_TOKEN Authorization: Bearer PRIVATE_BEARER"
	tests := []struct {
		name       string
		err        error
		category   string
		actionText string
	}{
		{"http-network", fmt.Errorf("%s: %w", privateError, errMCPHTTPTransport), "http_transport", "loopback broker"},
		{"authentication", fmt.Errorf("%s: %w", privateError, errMCPAuthDenied), "auth_denied", "configured credential"},
		{"expired-session", fmt.Errorf("%s: %w", privateError, errMCPSessionExpired), "session_expired", "fresh protocol session"},
		{"protocol-reconnect", fmt.Errorf("%s: %w", privateError, errMCPProtocolReconnect), "protocol_reconnect", "Reconnect the relay"},
		{"cancelled", fmt.Errorf("%s: %w", privateError, context.Canceled), "cancelled", "Reconcile"},
		{"deadline", fmt.Errorf("%s: %w", privateError, context.DeadlineExceeded), "deadline", "Reconcile"},
		{"unknown", errors.New(privateError), "unknown", "unknown reason"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := &fakeTransport{send: func(context.Context, *jsonrpc.Request) (*jsonrpc.Response, error) {
				return nil, test.err
			}}
			p := &proxy{remote: f, active: map[string]context.CancelFunc{}}
			req := &jsonrpc.Request{Id: "opaque", Method: "tools/call", Jsonrpc: "2.0", Params: json.RawMessage(`{"name":"act","arguments":{}}`)}
			res := &jsonrpc.Response{Id: req.Id, Jsonrpc: req.Jsonrpc}
			p.Serve(context.Background(), req, res)

			if f.calls.Load() != 1 || res.Id != req.Id || res.Error == nil || res.Error.Code != -32000 {
				t.Fatal("transport failure retried or lost its JSON-RPC error", f.calls.Load(), res)
			}
			if !strings.Contains(res.Error.Message, test.actionText) || !strings.Contains(res.Error.Message, "operation was not replayed") {
				t.Fatal("transport failure message omitted category guidance", test.name, res.Error.Message)
			}
			for _, forbidden := range []string{"private.invalid", "PRIVATE_TOKEN", "PRIVATE_BEARER", "Authorization"} {
				if strings.Contains(res.Error.Message, forbidden) || strings.Contains(string(res.Error.Data), forbidden) {
					t.Fatal("transport diagnostics disclosed private error text", test.name, forbidden)
				}
			}
			var data struct {
				Category       string `json:"category"`
				OperationState string `json:"operationState"`
			}
			if err := json.Unmarshal(res.Error.Data, &data); err != nil || data.Category != test.category || data.OperationState != "not_replayed" {
				t.Fatal("transport error category metadata mismatch", test.name, string(res.Error.Data), err)
			}
		})
	}
}
func TestCancellation(t *testing.T) {
	started := make(chan struct{})
	done := make(chan struct{})
	f := &fakeTransport{send: func(ctx context.Context, _ *jsonrpc.Request) (*jsonrpc.Response, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	p := &proxy{remote: f, active: map[string]context.CancelFunc{}}
	go func() {
		p.Serve(context.Background(), &jsonrpc.Request{Id: "active", Method: "tools/call"}, &jsonrpc.Response{})
		close(done)
	}()
	<-started
	p.OnNotification(context.Background(), &jsonrpc.Notification{Method: "notifications/cancelled", Params: json.RawMessage(`{"requestId":"active"}`)})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("request not cancelled")
	}
}
func TestProtocolRoutingHeaders(t *testing.T) {
	h := http.Header{}
	err := headers(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fixture"}}`), h)
	if err != nil || h.Get("Mcp-Method") != "tools/call" || h.Get("Mcp-Name") != "fixture" {
		t.Fatal("routing headers missing")
	}
}
