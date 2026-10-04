package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/viant/mechanize/model"
)

// Models the native helper's epoch checks without desktop APIs. Only doctor and
// apps.list are exempt; element refs are private to the creating helper epoch.
type readonlyGatewayFixture struct {
	mu           sync.Mutex
	epoch        string
	failSnapshot bool
	calls        []string
	reads        int
	doctor       map[string]any
}

func (f *readonlyGatewayFixture) Close() error { return nil }
func (f *readonlyGatewayFixture) Call(ctx context.Context, r Request) (Reply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method)
	reply := Reply{ProtocolVersion: 1, RequestID: r.RequestID, HelperEpoch: f.epoch}
	if r.Method != "doctor" && r.Method != "apps.list" && r.HelperEpoch != f.epoch {
		return reply, nativeError("staleEpoch", "helper epoch differs")
	}
	var result any
	switch r.Method {
	case "doctor":
		result = f.doctor
		if result == nil {
			result = map[string]any{"axTrusted": true}
		}
	case "apps.list":
		result = map[string]any{"complete": true, "apps": []map[string]any{{"pid": 1, "bundleID": "fixture.app", "launchTime": "launch"}}}
	case "elements.snapshot":
		if f.failSnapshot {
			return Reply{}, &TransportError{Cause: context.DeadlineExceeded, DispatchState: "unknown"}
		}
		result = map[string]any{"observationId": "obs-" + f.epoch, "generation": 1, "complete": true, "nodes": []map[string]any{{"ref": "ref-" + f.epoch, "identifier": "save", "nativeRole": "AXButton"}}, "startedAt": "2026-10-03T00:00:00Z", "returnedAt": "2026-10-03T00:00:00Z"}
	case "elements.read":
		f.reads++
		result = map[string]any{"values": map[string]any{"enabled": true}}
	default:
		return reply, errors.New("unexpected method")
	}
	reply.Result, _ = json.Marshal(result)
	return reply, nil
}
func newReadonlyGateway(t *testing.T, r Caller) *Gateway {
	t.Helper()
	g, err := NewGateway(r, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func TestReadOnlyGatewayRecoversFreshObservationAndRejectsOldElementEpoch(t *testing.T) {
	ctx, p := nativeActor(t)
	old := &readonlyGatewayFixture{epoch: "old"}
	fresh := &readonlyGatewayFixture{epoch: "fresh"}
	creates := 0
	r, _ := NewReadOnlyCaller(old, func(context.Context) (Caller, error) { creates++; return fresh, nil })
	defer r.Close()
	g := newReadonlyGateway(t, r)
	surface := model.Surface{Kind: "native", BundleID: "fixture.app"}
	before, err := g.Observe(ctx, p, surface)
	if err != nil {
		t.Fatal(err)
	}
	old.failSnapshot = true
	if _, err = g.Observe(ctx, p, surface); !errors.Is(err, context.DeadlineExceeded) || creates != 0 {
		t.Fatal("failed observation replayed", err, creates)
	}
	after, err := g.Observe(ctx, p, surface)
	if err != nil || after.Epoch != "fresh" || after.Sequence != 1 || creates != 1 {
		t.Fatal(after, err, creates)
	}
	if after.Nodes[0].Ref.Epoch == before.Nodes[0].Ref.Epoch || after.Nodes[0].Ref.ID == before.Nodes[0].Ref.ID {
		t.Fatal("fresh snapshot reused old refs")
	}
	params, _ := json.Marshal(map[string]any{"elementRef": before.Nodes[0].Ref.ID, "generation": before.Nodes[0].Ref.Generation, "attributes": []string{"enabled"}})
	if _, err = r.Call(ctx, Request{RequestID: "old-ref", Method: "elements.read", HelperEpoch: before.Epoch, Params: params}); err == nil {
		t.Fatal("old element epoch accepted")
	}
	if fresh.reads != 0 {
		t.Fatal("stale reference reached attribute read")
	}
	step := nativeStep("element.read")
	step.Effect.Class = model.ReadOnly
	step.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: "enabled"}}
	result, err := g.Execute(ctx, p, step, nil)
	if err != nil || result.Value == nil || !result.Value.Bool || fresh.reads != 1 {
		t.Fatal("fresh read unusable", result, err)
	}
}
func TestReadOnlyGatewaySharedCallerRefreshesEachCachedGateway(t *testing.T) {
	ctx, p := nativeActor(t)
	old := &readonlyGatewayFixture{epoch: "old", doctor: map[string]any{"axTrusted": true, "mutationEnabled": true, "semanticEnabled": true, "targetedKeyboardEnabled": true, "sessionKeyboardEnabled": true, "launchEnabled": true}}
	fresh := &readonlyGatewayFixture{epoch: "fresh"}
	creates := 0
	r, _ := NewReadOnlyCaller(old, func(context.Context) (Caller, error) { creates++; return fresh, nil })
	defer r.Close()
	first, second := newReadonlyGateway(t, r), newReadonlyGateway(t, r)
	surface := model.Surface{Kind: "native", BundleID: "fixture.app"}
	for _, g := range []*Gateway{first, second} {
		if _, err := g.Observe(ctx, p, surface); err != nil {
			t.Fatal(err)
		}
		g.installed = Lease{ID: "old", Generation: 1}
	}
	old.failSnapshot = true
	if _, err := first.Observe(ctx, p, surface); err == nil {
		t.Fatal("timeout missing")
	}
	for _, g := range []*Gateway{second, first} {
		obs, err := g.Observe(ctx, p, surface)
		if err != nil || obs.Epoch != "fresh" || obs.Sequence != 1 {
			t.Fatal(obs, err)
		}
		if g.mutationEnabled || g.semanticEnabled || g.targetedKeyboardEnabled || g.sessionKeyboardEnabled || g.launchEnabled || g.installed.ID != "" {
			t.Fatal("cached old qualification or lease survived restart")
		}
	}
	if creates != 1 {
		t.Fatal("shared gateways created extra helpers", creates)
	}
	doctors := 0
	for _, method := range fresh.calls {
		if method == "doctor" {
			doctors++
		}
	}
	if doctors != 2 {
		t.Fatal("each gateway must refresh doctor evidence", doctors)
	}
}
