package containerbrowser

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/viant/jsonrpc"
	"github.com/viant/jsonrpc/transport"
	"github.com/viant/mcp-protocol/client"
	"github.com/viant/mcp-protocol/logger"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	server "github.com/viant/mcp/server"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

type Source struct {
	Source string `json:"source"`
}
type Empty struct{}
type ScreenshotInput struct {
	Scale *float64 `json:"scale,omitempty"`
}
type Result struct {
	Status    string                     `json:"status"`
	Values    map[string]json.RawMessage `json:"values,omitempty"`
	Code      string                     `json:"code,omitempty"`
	Outcome   string                     `json:"outcome,omitempty"`
	CompileMS int64                      `json:"compileMs,omitempty"`
	BrowserMS int64                      `json:"browserMs,omitempty"`
	ElapsedMS int64                      `json:"elapsedMs,omitempty"`
}
type browserSession struct {
	id          string
	lane        chan struct{}
	mu          sync.Mutex
	registered  bool
	terminated  bool
	transportID string
}
type Host struct {
	Worker      *Worker
	Policy      script.Policy
	Timeout     time.Duration
	mu          sync.Mutex
	sessions    map[transport.Notifier]*browserSession
	byTransport map[string]*browserSession
}

func BrowserCapabilities() map[string]bool {
	capabilities := map[string]bool{}
	for _, name := range []string{"browser.openOrigin", "browser.navigate", "browser.activate", "semanticPress", "replaceValue", "ensureChecked", "selectOption", "targetedKeyboard", "targetedFocus", "attributeRead", "boundedObservation", "roleLocator", "idLocator", "testIdLocator", "textLocator", "labelRelationships", "ancestorScope", "indexedQuery", "orderedQuery", "checkedObservation"} {
		capabilities["web:"+name] = true
	}
	return capabilities
}
func NewHost(worker *Worker, policy script.Policy, timeout time.Duration) (*Host, *server.Server, error) {
	if worker == nil || timeout <= 0 {
		return nil, nil, errors.New("worker and operation timeout required")
	}
	policy.Capabilities = BrowserCapabilities()
	h := &Host{Worker: worker, Policy: policy, Timeout: timeout, sessions: map[transport.Notifier]*browserSession{}, byTransport: map[string]*browserSession{}}
	factory := func(ctx context.Context, n transport.Notifier, log logger.Logger, c client.Operations) (protocol.Handler, error) {
		var entropy [16]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, err
		}
		s := &browserSession{id: hex.EncodeToString(entropy[:]), lane: make(chan struct{}, 1)}
		if err := s.authorize(ctx); err != nil {
			return nil, err
		}
		if capture, ok := ctx.Value(sessionCaptureKey{}).(*sessionCapture); ok {
			capture.session = s
		}
		h.mu.Lock()
		h.sessions[n] = s
		h.mu.Unlock()
		base := protocol.NewDefaultHandler(n, log, c)
		if err := protocol.RegisterTool[*ScreenshotInput, *Result](base.Registry, "mechanize_browser_screenshot", "Capture current tab as PNG image content. Optional scale > 0 and <= 1 reduces image dimensions without changing page layout.", func(ctx context.Context, in *ScreenshotInput) (*schema.CallToolResult, *jsonrpc.Error) {
			scale := 1.0
			if in != nil && in.Scale != nil {
				scale = *in.Scale
			}
			return h.inspect(ctx, s, "screenshot", scale)
		}); err != nil {
			return nil, err
		}
		for name, method := range map[string]string{"mechanize_browser_dom": "dom"} {
			if err := protocol.RegisterTool[*Empty, *Result](base.Registry, name, "Read the current owned browser tab. Open an allowed origin with DSL first. DOM is bounded HTML and text; screenshot is viewport PNG.", func(ctx context.Context, _ *Empty) (*schema.CallToolResult, *jsonrpc.Error) {
				return h.inspect(ctx, s, method)
			}); err != nil {
				return nil, err
			}
		}
		if err := protocol.RegisterTool[*Source, *Result](base.Registry, "mechanize_script_run", "Execute browser-only Mechanize DSL in this MCP session's isolated Chromium tab.", func(ctx context.Context, in *Source) (*schema.CallToolResult, *jsonrpc.Error) {
			return h.run(ctx, s, in)
		}); err != nil {
			return nil, err
		}
		if err := protocol.RegisterTool[*Source, *Result](base.Registry, "mechanize_script_validate", "Validate browser DSL and configured capabilities without launching Chromium.", func(ctx context.Context, in *Source) (*schema.CallToolResult, *jsonrpc.Error) {
			_, err := h.compile(in)
			if err != nil {
				return failureResult("validation", "notDispatched")
			}
			return toolResult(Result{Status: "valid"})
		}); err != nil {
			return nil, err
		}
		if err := protocol.RegisterTool[*Empty, *Result](base.Registry, "mechanize_session_close", "Terminate this session's browser resources immediately.", func(ctx context.Context, _ *Empty) (*schema.CallToolResult, *jsonrpc.Error) {
			if err := s.authorize(ctx); err != nil {
				return failureResult("unauthorized", "notDispatched")
			}
			if err := h.closeSession(s); err != nil {
				return failureResult("cleanupFailed", "unknown")
			}
			return toolResult(Result{Status: "closed"})
		}); err != nil {
			return nil, err
		}
		if err := protocol.RegisterTool[*Empty, *Result](base.Registry, "mechanize_capabilities", "Discover supported browser capabilities; native actions are unavailable.", func(ctx context.Context, _ *Empty) (*schema.CallToolResult, *jsonrpc.Error) {
			return toolResult(map[string]any{"capabilities": policy.Capabilities, "sourceFormats": []string{"dsl"}, "idleTimeoutSeconds": 300})
		}); err != nil {
			return nil, err
		}
		return base, nil
	}
	srv, err := server.New(server.WithImplementation(schema.Implementation{Name: "mechanize-browser", Version: "0.1.0"}), server.WithNewHandler(factory), server.WithStreamableURI("/mcp"), server.WithOnSessionClose(func(n transport.Notifier) {
		h.mu.Lock()
		s := h.sessions[n]
		delete(h.sessions, n)
		if s != nil {
			delete(h.byTransport, s.transportID)
		}
		h.mu.Unlock()
		if s != nil {
			_ = h.closeSession(s)
		}
	}))
	return h, srv, err
}
func (h *Host) compile(in *Source) (*model.Plan, error) {
	if in == nil {
		return nil, errors.New("source required")
	}
	p, err := script.Compile(in.Source)
	if err != nil {
		return nil, err
	}
	if len(p.Steps) > 100 {
		return nil, errors.New("operation exceeds 100 steps")
	}
	if err = (script.Validator{}).CheckPolicy(p, h.Policy); err != nil {
		return nil, err
	}
	return p, nil
}
func (h *Host) run(parent context.Context, s *browserSession, in *Source) (*schema.CallToolResult, *jsonrpc.Error) {
	started := time.Now()
	defer func() {
		log.Printf("browser operation session=%s elapsed_ms=%d", s.id, time.Since(started).Milliseconds())
	}()
	if err := s.authorize(parent); err != nil {
		return failureResult("unauthorized", "notDispatched")
	}
	p, err := h.compile(in)
	compileMS := time.Since(started).Milliseconds()
	if err != nil {
		return failureResult("validation", "notDispatched")
	}
	select {
	case s.lane <- struct{}{}:
		defer func() { <-s.lane }()
	default:
		return failureResult("sessionBusy", "notDispatched")
	}
	ctx, cancel := context.WithTimeout(parent, h.Timeout)
	defer cancel()
	s.mu.Lock()
	if s.terminated {
		s.mu.Unlock()
		return failureResult("sessionTerminated", "notDispatched")
	}
	if !s.registered {
		_, err = h.Worker.Call(ctx, "register", s.id, nil)
		if err == nil {
			s.registered = true
		}
	}
	s.mu.Unlock()
	if err != nil {
		return failureResult("browserUnavailable", "notDispatched")
	}
	bindings := map[string]model.Value{}
	values := map[string]json.RawMessage{}
	var browserMS int64
	for _, original := range p.Steps {
		step := original
		step.Target, err = step.Target.Resolve(bindings)
		if err != nil {
			return failureResult("binding", "notDispatched")
		}
		step.Arguments, err = step.ResolveArguments(bindings)
		if err != nil {
			return failureResult("binding", "notDispatched")
		}
		if step.Assertion != nil && step.Assertion.Expected != nil {
			copied := *step.Assertion
			v, e := model.ResolveValue(*copied.Expected, bindings)
			if e != nil {
				return failureResult("binding", "notDispatched")
			}
			copied.Expected = &v
			step.Assertion = &copied
		}
		browserStart := time.Now()
		raw, e := h.Worker.Call(ctx, "execute", s.id, &step)
		browserMS += time.Since(browserStart).Milliseconds()
		if e != nil {
			if ctx.Err() != nil {
				_ = h.closeSession(s)
				code := "canceled"
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					code = "deadline"
				}
				return failureResult(code, "unknown")
			}
			var typed *WorkerError
			if errors.As(e, &typed) {
				return failureResult(typed.Code, typed.Outcome)
			}
			return failureResult("browserUnavailable", "unknown")
		}
		if step.Bind != "" {
			var value any
			if json.Unmarshal(raw, &value) != nil {
				return failureResult("invalidBrowserResult", "unknown")
			}
			v, e := typedValue(value)
			if e != nil {
				return failureResult("unsupportedResult", "unknown")
			}
			bindings["binding."+step.Bind] = v
			values[step.Bind] = raw
		}
	}
	return toolResult(Result{Status: "completed", Values: values, Outcome: "unverified", CompileMS: compileMS, BrowserMS: browserMS, ElapsedMS: time.Since(started).Milliseconds()})
}

func (s *browserSession) authorize(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminated {
		return errors.New("session terminated")
	}
	return ctx.Err()
}
func typedValue(value any) (model.Value, error) {
	switch v := value.(type) {
	case string:
		return model.Value{Kind: model.StringValue, String: v}, nil
	case bool:
		return model.Value{Kind: model.BoolValue, Bool: v}, nil
	case []any:
		out := model.Value{Kind: model.ArrayValue}
		for _, item := range v {
			x, e := typedValue(item)
			if e != nil {
				return model.Value{}, e
			}
			out.Array = append(out.Array, x)
		}
		return out, nil
	default:
		return model.Value{}, errors.New("unsupported browser value")
	}
}
func (h *Host) closeSession(s *browserSession) error {
	s.mu.Lock()
	s.terminated = true
	registered := s.registered
	s.mu.Unlock()
	if !registered {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := h.Worker.Call(ctx, "terminate", s.id, nil)
	return err
}
func (h *Host) Close() error {
	h.mu.Lock()
	sessions := h.sessions
	h.sessions = map[transport.Notifier]*browserSession{}
	h.mu.Unlock()
	var failures []error
	for _, s := range sessions {
		if err := h.closeSession(s); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
func toolResult(value any) (*schema.CallToolResult, *jsonrpc.Error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, jsonrpc.NewInternalError("cannot encode browser result", nil)
	}
	return &schema.CallToolResult{Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: string(raw)}}}, nil
}
func failureResult(code, outcome string) (*schema.CallToolResult, *jsonrpc.Error) {
	result, err := toolResult(Result{Status: "failed", Code: code, Outcome: outcome})
	yes := true
	result.IsError = &yes
	return result, err
}
