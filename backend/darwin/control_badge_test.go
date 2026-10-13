package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
	"time"
)

type badgeFixture struct {
	calls  []Request
	status string
	extra  bool
}

func (f *badgeFixture) Close() error { return nil }
func (f *badgeFixture) Call(ctx context.Context, r Request) (Reply, error) {
	f.calls = append(f.calls, r)
	value := map[string]any{"status": f.status}
	if r.Method == "doctor" {
		value = map[string]any{"axTrusted": true}
	}
	switch r.Method {
	case "apps.list":
		value = map[string]any{"complete": true, "apps": []map[string]any{{"pid": 1, "bundleID": "fixture.app", "launchTime": "launch"}}}
	case "elements.snapshot":
		value = map[string]any{"observationId": "badge-observation", "generation": 1, "complete": true, "nodes": []map[string]any{{"ref": "badge-ref", "identifier": "save", "nativeRole": "AXButton"}}, "startedAt": "2026-10-03T00:00:00Z", "returnedAt": "2026-10-03T00:00:00Z"}
	case "elements.read":
		value = map[string]any{"values": map[string]any{"enabled": true}}
	}
	if f.extra && r.Method != "doctor" {
		value["content"] = "PRIVATE-CANARY"
	}
	data, _ := json.Marshal(value)
	return Reply{ProtocolVersion: 1, RequestID: r.RequestID, HelperEpoch: "badge-fixture", Result: data}, nil
}
func badgeContext() (context.Context, auth.Principal) {
	p, _ := auth.NewPrincipal("fixture", "", "badge-user", []string{"desktop:observe"})
	p.ClientID = "badge-client"
	return auth.WithPrincipal(context.Background(), p), p
}
func TestControlBadgeSessionOwnershipIsOpaqueAndExplicitlyReleased(t *testing.T) {
	f := &badgeFixture{status: "shown"}
	g, _ := NewGateway(f, GatewayOptions{AllApplications: true})
	ctx, p := badgeContext()
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "fixture-session", GrantID: "grant", Purpose: "observe"})
	target := ControlBadgeTarget{BundleID: "com.google.Chrome", ProcessID: 42, ProcessStartToken: "1790000000:1", WindowBounds: CaptureBounds{Width: 900, Height: 700}}
	_, err := g.BeginControlBadge(ctx, p, strings.Repeat("b", 64), target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var params map[string]any
	json.Unmarshal(f.calls[len(f.calls)-1].Params, &params)
	token := presentationSession(ctx)
	if len(token) != 64 || params["sessionToken"] != token || strings.Contains(string(f.calls[len(f.calls)-1].Params), "fixture-session") {
		t.Fatal("missing opaque session ownership")
	}
	other := p
	other.ClientID = "other"
	if badgeSessionToken(other, "fixture-session") == token {
		t.Fatal("foreign client shares presentation ownership")
	}
	_, err = g.call(ctx, "apps.list", map[string]any{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.calls[len(f.calls)-1].PresentationSession != token {
		t.Fatal("native action path omitted session ownership")
	}
	_, err = g.ReleaseControlBadgeSession(ctx, p, "fixture-session")
	if err != nil {
		t.Fatal(err)
	}
	r := f.calls[len(f.calls)-1]
	json.Unmarshal(r.Params, &params)
	if r.Method != "controlBadge.releaseSession" || r.Lease != nil || params["sessionToken"] != token {
		t.Fatal("exact session release missing")
	}
}
func TestControlBadgePresentationStrictUnleasedBoundedWire(t *testing.T) {
	f := &badgeFixture{status: "shown"}
	g, _ := NewGateway(f, GatewayOptions{AllApplications: true})
	ctx, p := badgeContext()
	target := ControlBadgeTarget{BundleID: "com.google.Chrome", ProcessID: 42, ProcessStartToken: "1790000000:1", WindowBounds: CaptureBounds{X: 0, Y: 26, Width: 900, Height: 700}}
	token := strings.Repeat("a", 64)
	result, e := g.BeginControlBadge(ctx, p, token, target, time.Second)
	if e != nil || result.Status != "shown" {
		t.Fatal(result, e)
	}
	r := f.calls[len(f.calls)-1]
	if r.Method != "controlBadge.begin" || r.Lease != nil || r.DeadlineRemainingMS > 1000 || r.DeadlineRemainingMS <= 0 {
		t.Fatal(r)
	}
	var params map[string]any
	json.Unmarshal(r.Params, &params)
	if len(params) != 6 || params["token"] != token || params["expectedApp"] != "com.google.Chrome" {
		t.Fatal(params)
	}
	f.status = "placementUnavailable"
	if reply, err := g.RenewControlBadge(ctx, p, token, time.Second); err != nil || reply.Status != "placementUnavailable" {
		t.Fatal("closed placement status rejected", reply, err)
	}
	if f.calls[len(f.calls)-1].Lease != nil {
		t.Fatal("placement status created input authority")
	}
	f.status = "hidden"
	if r, e := g.RenewControlBadge(ctx, p, token, time.Second); e != nil || r.Status != "hidden" {
		t.Fatal(r, e)
	}
	if r, e := g.EndControlBadge(ctx, p, token); e != nil || r.Status != "hidden" {
		t.Fatal(r, e)
	}
	if _, e = g.BeginControlBadge(ctx, p, "bad", target, time.Second); e == nil {
		t.Fatal("unbounded owner accepted")
	}
	if _, e = g.RenewControlBadge(ctx, p, token, 6*time.Second); e == nil {
		t.Fatal("unbounded lifetime accepted")
	}
	f.extra = true
	if _, e = g.EndControlBadge(ctx, p, token); e == nil {
		t.Fatal("content accepted")
	}
}
func TestReadonlyCallerOnlyAddsPresentationMethods(t *testing.T) {
	for _, method := range []string{"controlBadge.begin", "controlBadge.renew", "controlBadge.end", "controlBadge.stop", "controlBadge.releaseSession"} {
		if !readonlyMethod(method) {
			t.Fatal(method)
		}
	}
	for _, method := range []string{"controlBadge.input", "app.activate", "input.key"} {
		if readonlyMethod(method) {
			t.Fatal(method)
		}
	}
}

func TestControlBadgeMutexWaitRespectsDeadlineWithoutCallingHelper(t *testing.T) {
	f := &badgeFixture{status: "shown"}
	g, err := NewGateway(f, GatewayOptions{AllApplications: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, p := badgeContext()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	g.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := g.RenewControlBadge(ctx, p, strings.Repeat("a", 64), time.Second); done <- err }()
	var result error
	returned := false
	select {
	case result = <-done:
		returned = true
	case <-time.After(150 * time.Millisecond):
	}
	// Always release the fixture mutex and join the caller, including baseline
	// failures, so the test cannot leak a blocked presentation goroutine.
	g.mu.Unlock()
	if !returned {
		result = <-done
	}
	if !returned {
		t.Error("presentation waited for gateway mutex beyond its deadline")
	}
	if result == nil {
		t.Error("expired presentation accepted")
	}
	if len(f.calls) != 0 {
		t.Fatalf("expired presentation reached helper %d times", len(f.calls))
	}
}

// Exercise the public gateway routes: observation and read-only AX work must
// carry the same session owner without requiring an input lease.
func TestAccessibilityObservationAndReadCarryPresentationSession(t *testing.T) {
	f := &badgeFixture{status: "shown"}
	readonly, err := NewReadOnlyCaller(f, func(context.Context) (Caller, error) { t.Fatal("unexpected helper replacement"); return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer readonly.Close()
	g, err := NewGateway(readonly, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, p := badgeContext()
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "ax-session", GrantID: "grant", Purpose: "observe"})
	observation, err := g.Observe(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"})
	if err != nil || len(observation.Nodes) != 1 {
		t.Fatal(observation, err)
	}
	step := nativeStep("element.read")
	step.Effect.Class = model.ReadOnly
	step.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: "enabled"}}
	result, err := g.Execute(ctx, p, step, nil)
	if err != nil || result.Value == nil || !result.Value.Bool {
		t.Fatal(result, err)
	}
	if len(presentationSession(ctx)) != 64 {
		t.Fatal("missing opaque presentation session")
	}
	seen := map[string]bool{}
	for _, request := range f.calls {
		if request.Method != "elements.snapshot" && request.Method != "elements.read" {
			continue
		}
		seen[request.Method] = true
		if request.PresentationSession != presentationSession(ctx) || request.Lease != nil {
			t.Fatalf("AX route lost presentation owner or gained input authority: %+v", request)
		}
	}
	if !seen["elements.snapshot"] || !seen["elements.read"] {
		t.Fatal("AX routes not exercised", seen)
	}
	if _, err = g.ReleaseControlBadgeSession(ctx, p, "ax-session"); err != nil {
		t.Fatal(err)
	}
	last := f.calls[len(f.calls)-1]
	if last.Method != "controlBadge.releaseSession" || last.Lease != nil {
		t.Fatal(last)
	}
}
