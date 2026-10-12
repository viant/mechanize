package host

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/session"
)

type browserBadgeCaller struct {
	mu        sync.Mutex
	methods   []string
	ended     chan struct{}
	failBegin bool
}

func (*browserBadgeCaller) Close() error { return nil }
func (c *browserBadgeCaller) Call(ctx context.Context, r native.Request) (native.Reply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.methods = append(c.methods, r.Method)
	if r.Method == "controlBadge.begin" && c.failBegin {
		return native.Reply{}, errors.New("lost presentation reply")
	}
	v := map[string]any{"status": "shown"}
	if r.Method == "doctor" {
		v = map[string]any{"axTrusted": true}
	}
	if r.Method == "controlBadge.end" || r.Method == "controlBadge.stop" {
		close(c.ended)
		v["status"] = "hidden"
	}
	data, _ := json.Marshal(v)
	return native.Reply{ProtocolVersion: 1, RequestID: r.RequestID, HelperEpoch: "badge-test", Result: data}, nil
}

func TestBrowserControlBadgeLostBeginReplyEndsExactAttempt(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "badge", []string{"desktop:observe"})
	p.ClientID = "test-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	c := &browserBadgeCaller{ended: make(chan struct{}), failBegin: true}
	g, _ := native.NewGateway(c, native.GatewayOptions{AllApplications: true})
	h := &Host{nativeByUser: map[string]*native.Gateway{p.Namespace: g}}
	if h.presentBrowserControlBadge(ctx, p, session.ProcessIdentity{PID: 12, StartToken: "1790000000:1", Executable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}, chrome.ControlBadgeWindow{X: 0, Y: 20, Width: 900, Height: 700}) != nil {
		t.Fatal("lost begin returned active lifetime")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var begins, ends int
	for _, method := range c.methods {
		if method == "controlBadge.begin" {
			begins++
		}
		if method == "controlBadge.stop" {
			ends++
		}
	}
	if begins != 1 || ends != 1 {
		t.Fatalf("begin replay or missing exact cleanup: %d/%d", begins, ends)
	}
}
func TestBrowserControlBadgeEndsOnceOnCancelledOperation(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "badge", []string{"desktop:observe"})
	p.ClientID = "test-client"
	ctx, cancel := context.WithCancel(auth.WithPrincipal(context.Background(), p))
	c := &browserBadgeCaller{ended: make(chan struct{})}
	g, _ := native.NewGateway(c, native.GatewayOptions{AllApplications: true})
	h := &Host{nativeByUser: map[string]*native.Gateway{p.Namespace: g}}
	end := h.presentBrowserControlBadge(ctx, p, session.ProcessIdentity{PID: 12, StartToken: "1790000000:1", Executable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}, chrome.ControlBadgeWindow{X: 0, Y: 20, Width: 900, Height: 700})
	if end == nil {
		t.Fatal("badge did not start")
	}
	cancel()
	select {
	case <-c.ended:
	case <-time.After(time.Second):
		t.Fatal("cancel did not end badge")
	}
	end()
	end()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, method := range c.methods {
		if method != "doctor" && method != "controlBadge.begin" && method != "controlBadge.end" {
			t.Fatalf("unexpected input/focus request %s", method)
		}
	}
}

// Closed helper statuses are presentation state, independent of transport errors.
type badgeStatusCaller struct {
	mu                       sync.Mutex
	requests                 []native.Request
	beginStatus, renewStatus string
	events                   chan native.Request
}

func (*badgeStatusCaller) Close() error { return nil }
func (c *badgeStatusCaller) Call(_ context.Context, r native.Request) (native.Reply, error) {
	c.mu.Lock()
	c.requests = append(c.requests, r)
	c.mu.Unlock()
	value := map[string]any{"status": "hidden"}
	switch r.Method {
	case "doctor":
		value = map[string]any{"axTrusted": true}
	case "controlBadge.begin":
		value["status"] = c.beginStatus
	case "controlBadge.renew":
		value["status"] = c.renewStatus
	}
	c.events <- r
	raw, _ := json.Marshal(value)
	return native.Reply{ProtocolVersion: 1, RequestID: r.RequestID, HelperEpoch: "badge-status-test", Result: raw}, nil
}
func statusBadgeFixture(t *testing.T, begin, renew string) (*badgeStatusCaller, func()) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "badge-status", []string{"desktop:observe"})
	p.ClientID = "status-client"
	ctx, cancel := context.WithCancel(auth.WithPrincipal(context.Background(), p))
	c := &badgeStatusCaller{beginStatus: begin, renewStatus: renew, events: make(chan native.Request, 16)}
	g, err := native.NewGateway(c, native.GatewayOptions{AllApplications: true})
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{nativeByUser: map[string]*native.Gateway{p.Namespace: g}}
	end := h.presentBrowserControlBadge(ctx, p, session.ProcessIdentity{PID: 12, StartToken: "1790000000:1", Executable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}, chrome.ControlBadgeWindow{Width: 900, Height: 700})
	t.Cleanup(func() {
		cancel()
		if end != nil {
			end()
		}
	})
	return c, end
}
func (c *badgeStatusCaller) waitMethod(method string, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case r := <-c.events:
			if r.Method == method {
				return true
			}
		case <-timer.C:
			return false
		}
	}
}
func (c *badgeStatusCaller) assertExactStop(t *testing.T, renews int) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	counts := map[string]int{}
	token := ""
	for _, r := range c.requests {
		if r.Method == "doctor" {
			continue
		}
		counts[r.Method]++
		var params struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(r.Params, &params) != nil || params.Token == "" {
			t.Fatal("missing presentation token")
		}
		if r.Method == "controlBadge.begin" {
			token = params.Token
		}
		if token == "" || params.Token != token {
			t.Fatal("cleanup changed presentation owner")
		}
	}
	if counts["controlBadge.begin"] != 1 || counts["controlBadge.renew"] != renews || counts["controlBadge.stop"] != 1 || counts["controlBadge.end"] != 0 || len(counts) != 2+min(renews, 1) {
		t.Fatalf("unexpected presentation lifecycle: %v", counts)
	}
}
func TestBrowserControlBadgeUnavailableBeginHasNoLifetime(t *testing.T) {
	c, end := statusBadgeFixture(t, "unavailable", "shown")
	if end != nil {
		t.Fatal("unavailable begin returned an active presentation handle")
	}
	c.assertExactStop(t, 0)
}
func TestBrowserControlBadgeUnavailableRenewStopsExactOwner(t *testing.T) {
	t.Parallel()
	c, end := statusBadgeFixture(t, "shown", "unavailable")
	if end == nil {
		t.Fatal("shown begin did not retain lifetime")
	}
	if !c.waitMethod("controlBadge.stop", 1500*time.Millisecond) {
		t.Fatal("unavailable renewal did not stop its exact owner")
	}
	end()
	end()
	c.assertExactStop(t, 1)
}
func TestBrowserControlBadgeHiddenRemainsRenewable(t *testing.T) {
	t.Parallel()
	c, end := statusBadgeFixture(t, "hidden", "hidden")
	if end == nil {
		t.Fatal("background target lost its valid presentation lifetime")
	}
	if !c.waitMethod("controlBadge.renew", 1500*time.Millisecond) || !c.waitMethod("controlBadge.renew", 1500*time.Millisecond) {
		t.Fatal("hidden foreground state stopped heartbeat")
	}
	c.mu.Lock()
	for _, r := range c.requests {
		if r.Method == "controlBadge.stop" || r.Method == "controlBadge.end" {
			c.mu.Unlock()
			t.Fatal("hidden target was prematurely retired")
		}
	}
	c.mu.Unlock()
	end()
	if !c.waitMethod("controlBadge.end", time.Second) {
		t.Fatal("normal completion did not end hidden owner")
	}
}
