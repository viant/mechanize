// mechanize-mcp-relay connects stdio clients to the running local broker.
// It never starts a broker or retries a failed operation.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/viant/jsonrpc"
	"github.com/viant/jsonrpc/transport"
	"github.com/viant/jsonrpc/transport/client/http/streamable"
	base "github.com/viant/jsonrpc/transport/server/base"
	"github.com/viant/scy"
)

const maxMessage = 4 << 20
const protocol = "2025-06-18"

var (
	errMCPHTTPTransport     = errors.New("MCP HTTP transport failed")
	errMCPAuthDenied        = errors.New("MCP authentication denied")
	errMCPSessionExpired    = errors.New("MCP session expired")
	errMCPProtocolReconnect = errors.New("MCP protocol reconnection failed")
)

func privateRead(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("private file unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("private file unavailable")
	}
	if !privateFileInfo(info) {
		return nil, errors.New("private regular file required")
	}
	return io.ReadAll(io.LimitReader(f, 1<<20))
}
func privateFileInfo(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid() && info.Mode().IsRegular() && info.Mode().Perm()&0077 == 0 && info.Size() <= 1<<20
}
func credential(ctx context.Context, path string) (string, error) {
	data, err := privateRead(path)
	if err != nil {
		return "", err
	}
	var cfg struct {
		Credential *scy.Resource `json:"stdioCredential"`
	}
	if json.Unmarshal(data, &cfg) != nil || cfg.Credential == nil {
		return "", errors.New("credential reference required")
	}
	r := cfg.Credential
	if !filepath.IsAbs(r.URL) || r.Key != "" || r.Fallback != nil || len(r.Data) > 0 {
		return "", errors.New("private file credential reference required")
	}
	data, err = privateRead(r.URL)
	if err != nil {
		return "", err
	}
	// Resolve the already validated private bytes through Scy, avoiding a second
	// pathname read (and its symlink replacement race).
	secret, err := scy.New().Load(ctx, &scy.Resource{URL: r.URL, Data: data})
	if err != nil {
		return "", errors.New("Scy credential unavailable")
	}
	token := strings.TrimSpace(secret.String())
	if len(token) < 32 || len(token) > 32768 || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("invalid credential")
	}
	return token, nil
}
func endpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("invalid endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() || u.User != nil || u.Path != "/mcp" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("loopback MCP endpoint required")
	}
	return nil
}

type secureTransport struct {
	endpoint       string
	loadCredential func(context.Context) (string, error)
	base           http.RoundTripper
}
type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, errors.New("MCP response limit exceeded")
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, e := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, e
}
func (t *secureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL == nil || endpoint(r.URL.String()) != nil || r.URL.String() != t.endpoint {
		return nil, errors.New("MCP endpoint refused")
	}
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	if t.loadCredential == nil || t.base == nil {
		return nil, errors.New("MCP credential unavailable")
	}
	token, err := t.loadCredential(r.Context())
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, errors.New("MCP credential unavailable")
	}
	if len(token) < 32 || len(token) > 32768 || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("MCP credential unavailable")
	}
	clone := r.Clone(r.Context())
	clone.Header = r.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+token)
	clone.Header.Set("Accept", "application/json, text/event-stream")
	res, err := t.base.RoundTrip(clone)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, errMCPHTTPTransport
	}
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		res.Body.Close()
		return nil, errMCPAuthDenied
	}
	// MCP stateful-session 404 requires a fresh protocol session. Never surface
	// it as a tool response or transparently resend the failed operation.
	if res.StatusCode == http.StatusNotFound && clone.Header.Get("Mcp-Session-Id") != "" {
		res.Body.Close()
		return nil, errMCPSessionExpired
	}
	res.Body = &boundedBody{ReadCloser: res.Body, remaining: 32 << 20}
	return res, nil
}

type proxy struct {
	remote transport.Transport
	mu     sync.Mutex
	active map[string]context.CancelFunc
}

func idKey(id any) string { b, _ := json.Marshal(id); return string(b) }

func transportFailure(err error) (string, string) {
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled", "Mechanize request was cancelled; its outcome may be uncertain. Reconcile before retrying; the operation was not replayed."
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline", "Mechanize request deadline elapsed; its outcome may be uncertain. Reconcile before retrying; the operation was not replayed."
	case errors.Is(err, errMCPAuthDenied):
		return "auth_denied", "Mechanize authentication was denied. Check the configured credential before a new call; the operation was not replayed."
	case errors.Is(err, errMCPSessionExpired):
		return "session_expired", "Mechanize MCP session expired. Establish a fresh protocol session before continuing; the operation was not replayed."
	case errors.Is(err, errMCPProtocolReconnect):
		return "protocol_reconnect", "Mechanize protocol reconnection failed. Reconnect the relay before continuing; the operation was not replayed."
	case errors.Is(err, errMCPHTTPTransport):
		return "http_transport", "Mechanize HTTP transport failed. Check loopback broker availability; the operation was not replayed."
	default:
		return "unknown", "Mechanize transport failed for an unknown reason. Reconcile before retrying; the operation was not replayed."
	}
}

func (p *proxy) Serve(ctx context.Context, req *jsonrpc.Request, res *jsonrpc.Response) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	key := idKey(req.Id)
	p.mu.Lock()
	p.active[key] = cancel
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.active, key); p.mu.Unlock() }()
	if req.Method == "initialize" {
		// Negotiate the stateful protocol supported by the deployed broker. Newer
		// stdio clients accept the server's advertised earlier protocol version.
		var params map[string]json.RawMessage
		if json.Unmarshal(req.Params, &params) != nil {
			res.Error = jsonrpc.NewError(-32602, "invalid initialization", nil)
			return
		}
		params["protocolVersion"] = json.RawMessage(`"` + protocol + `"`)
		req.Params, _ = json.Marshal(params)
	}
	reply, err := p.remote.Send(ctx, req)
	if err != nil {
		category, message := transportFailure(err)
		res.Error = jsonrpc.NewError(-32000, message, map[string]string{
			"category":       category,
			"operationState": "not_replayed",
		})
		return
	}
	*res = *reply
}
func (p *proxy) OnNotification(ctx context.Context, n *jsonrpc.Notification) {
	if n.Method == "notifications/cancelled" {
		var v struct {
			RequestID any `json:"requestId"`
		}
		if json.Unmarshal(n.Params, &v) == nil {
			p.mu.Lock()
			cancel := p.active[idKey(v.RequestID)]
			p.mu.Unlock()
			if cancel != nil {
				cancel()
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = p.remote.Notify(ctx, n)
}
func headers(_ context.Context, data []byte, h http.Header) error {
	var v struct {
		ID     json.RawMessage            `json:"id"`
		Method string                     `json:"method"`
		Params map[string]json.RawMessage `json:"params"`
	}
	if json.Unmarshal(data, &v) != nil {
		return errors.New("invalid RPC message")
	}
	if len(v.ID) == 0 || v.Method == "" {
		return nil
	}
	h.Set("Mcp-Method", v.Method)
	field := ""
	switch v.Method {
	case "tools/call", "prompts/get":
		field = "name"
	case "resources/read":
		field = "uri"
	}
	if field != "" {
		var name string
		if json.Unmarshal(v.Params[field], &name) != nil {
			return errors.New("missing routing name")
		}
		h.Set("Mcp-Name", name)
	}
	return nil
}
func run(ctx context.Context, config, rawURL string, input io.Reader, output io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := endpoint(rawURL); err != nil {
		return err
	}
	_, err := credential(ctx, config)
	if err != nil {
		return err
	}
	local := &proxy{active: map[string]context.CancelFunc{}}
	remote := &proxy{active: map[string]context.CancelFunc{}}
	httpBase := http.DefaultTransport.(*http.Transport).Clone()
	httpBase.Proxy = nil
	defer httpBase.CloseIdleConnections()
	httpClient := &http.Client{Transport: &secureTransport{endpoint: rawURL, loadCredential: func(requestCtx context.Context) (string, error) { return credential(requestCtx, config) }, base: httpBase}, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	client, err := streamable.New(ctx, rawURL, streamable.WithHTTPClient(httpClient), streamable.WithHandler(remote), streamable.WithProtocolVersion(protocol), streamable.WithRequestHeaderProvider(headers), streamable.WithRunTimeout(0))
	if err != nil {
		return errors.New("MCP client unavailable")
	}
	managed := newRecoveringTransport(ctx, client, func(owner context.Context) (connection, error) {
		return streamable.New(owner, rawURL, streamable.WithHTTPClient(httpClient), streamable.WithHandler(remote), streamable.WithProtocolVersion(protocol), streamable.WithRequestHeaderProvider(headers), streamable.WithRunTimeout(0))
	})
	defer managed.Close()
	local.remote = managed
	session := base.NewSession(ctx, "stdio", output, func(context.Context, transport.Transport) transport.Handler { return local }, base.WithFramer(func(b []byte) []byte { return append(b, '\n') }))
	remote.remote = base.NewTransport(session.RoundTrips, session.SendData, session)
	dispatcher := base.NewHandler()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxMessage)
	slots := make(chan struct{}, 32)
	var pending sync.WaitGroup
	defer func() { cancel(); pending.Wait() }()
	for scanner.Scan() {
		data := bytes.Clone(scanner.Bytes())
		if !json.Valid(data) {
			return errors.New("invalid MCP input")
		}
		var msg struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		if json.Unmarshal(data, &msg) != nil {
			return errors.New("invalid MCP input")
		}
		if msg.Method == "" || len(msg.ID) == 0 {
			dispatcher.HandleMessage(ctx, session, data, nil)
			continue
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		pending.Add(1)
		go func() {
			defer pending.Done()
			defer func() { <-slots }()
			dispatcher.HandleMessage(ctx, session, data, nil)
		}()
	}
	return scanner.Err()
}
func main() {
	jsonrpc.DefaultLogger = jsonrpc.NewStdLogger(io.Discard)
	config := flag.String("config", "", "private Mechanize config path")
	url := flag.String("url", "http://127.0.0.1:4987/mcp", "running loopback MCP endpoint")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	// Context cancellation also interrupts an idle stdin reader.
	go func() { <-ctx.Done(); _ = os.Stdin.Close() }()
	if err := run(ctx, *config, *url, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Mechanize MCP relay stopped")
		os.Exit(1)
	}
}
