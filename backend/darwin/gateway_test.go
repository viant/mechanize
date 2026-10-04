package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
)

type gatewayFixture struct {
	calls    []string
	nodes    []map[string]any
	complete bool
	mutation bool
}

func (f *gatewayFixture) Close() error { return nil }
func (f *gatewayFixture) Call(ctx context.Context, r Request) (Reply, error) {
	f.calls = append(f.calls, r.Method)
	result := any(map[string]any{})
	reply := Reply{ProtocolVersion: 1, RequestID: r.RequestID, HelperEpoch: "fixture"}
	switch r.Method {
	case "doctor":
		result = map[string]any{"axTrusted": true, "mutationEnabled": f.mutation, "nativeWindowScopes": []string{"exactTitle"}}
	case "apps.list":
		result = map[string]any{"complete": true, "apps": []map[string]any{{"pid": 1, "bundleID": "fixture.app", "launchTime": "launch"}}}
	case "elements.snapshot":
		var params struct {
			WindowScope map[string]string `json:"windowScope"`
		}
		json.Unmarshal(r.Params, &params)
		nodes := f.nodes
		if len(params.WindowScope) > 0 {
			root := ""
			byID := map[string]map[string]any{}
			for _, node := range nodes {
				ref, _ := node["ref"].(string)
				byID[ref] = node
				if node["nativeRole"] == "AXWindow" && node["name"] == params.WindowScope["title"] {
					if root != "" {
						return reply, &NativeError{Code: "ambiguousTarget", DispatchState: "notDispatched"}
					}
					root = ref
				}
			}
			if root == "" {
				return reply, &NativeError{Code: "targetNotFound", DispatchState: "notDispatched"}
			}
			selected := []map[string]any{}
			for _, node := range nodes {
				ref, _ := node["ref"].(string)
				included := ref == root
				parent, _ := node["parentRef"].(string)
				for depth := 0; parent != "" && depth < 20; depth++ {
					if parent == root {
						included = true
						break
					}
					parent, _ = byID[parent]["parentRef"].(string)
				}
				if included {
					copy := map[string]any{}
					for key, value := range node {
						copy[key] = value
					}
					if ref == root {
						copy["parentRef"] = ""
					}
					selected = append(selected, copy)
				}
			}
			nodes = selected
		}
		result = map[string]any{"observationId": "obs", "generation": 1, "complete": f.complete, "nodes": nodes, "windowScope": params.WindowScope, "startedAt": "2026-10-01T00:00:00Z", "returnedAt": "2026-10-01T00:00:00Z"}
	case "elements.read":
		result = map[string]any{"values": map[string]any{"name": "Save", "value": "literal ${data}"}}
	case "elements.press", "elements.setValue":
		reply.Receipt = &Receipt{DispatchState: "dispatched"}
	}
	reply.Result, _ = json.Marshal(result)
	return reply, nil
}
func nativeActor(t *testing.T) (context.Context, auth.Principal) {
	t.Helper()
	p, err := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	return auth.WithPrincipal(context.Background(), p), p
}
func nativeStep(action string) model.Step {
	return model.Step{ID: "step", Action: action, TimeoutMs: 1000, Effect: model.Effect{Class: model.ExternalNonIdempotent}, Target: model.Selector{Surface: model.Surface{Kind: "native", BundleID: "fixture.app"}, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "save"}, Exact: true}}}
}
func newGatewayFixture(t *testing.T, fixture *gatewayFixture, lease bool) *Gateway {
	t.Helper()
	options := GatewayOptions{AllowedBundles: []string{"fixture.app"}}
	if lease {
		options.Lease = func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "desktop", Generation: 1}, nil }
	}
	g, err := NewGateway(fixture, options)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func TestGatewayScopesAmbiguityAndCoverageStopBeforeDispatch(t *testing.T) {
	ctx, p := nativeActor(t)
	node := map[string]any{"ref": "ref", "nativeRole": "AXButton", "identifier": "save", "name": "Save", "enabled": true}
	for _, tc := range []struct {
		name     string
		nodes    []map[string]any
		complete bool
		scope    bool
	}{{"duplicate", []map[string]any{node, node}, true, false}, {"partial", []map[string]any{node}, false, false}, {"scope", []map[string]any{node}, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := &gatewayFixture{nodes: tc.nodes, complete: tc.complete, mutation: true}
			g := newGatewayFixture(t, fixture, true)
			step := nativeStep("element.press")
			if tc.scope {
				step.Target.Scope.Window = map[string]model.Value{"title": {Kind: model.StringValue, String: "Fixture"}}
			}
			result, err := g.Execute(ctx, p, step, nil)
			if err == nil || result.DispatchState != "notDispatched" {
				t.Fatalf("unsafe result: %+v %v", result, err)
			}
			for _, method := range fixture.calls {
				if method == "elements.press" || method == "lease.install" {
					t.Fatal("input authority used after failed target gate")
				}
			}
		})
	}
}
func TestGatewayDispatchRemainsUnverified(t *testing.T) {
	ctx, p := nativeActor(t)
	fixture := &gatewayFixture{complete: true, mutation: true, nodes: []map[string]any{{"ref": "ref", "nativeRole": "AXButton", "identifier": "save", "enabled": true}}}
	g := newGatewayFixture(t, fixture, true)
	result, err := g.Execute(ctx, p, nativeStep("element.press"), nil)
	if err != nil || result.DispatchState != "dispatched" || result.VerificationState != "unknown" {
		t.Fatalf("false success: %+v %v", result, err)
	}
	if epoch, err := g.LeaseEpoch(ctx, p); err != nil || epoch != 1 {
		t.Fatalf("fence: %d %v", epoch, err)
	}
}
func TestGatewayValueReadPolicy(t *testing.T) {
	ctx, p := nativeActor(t)
	fixture := &gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "ref", "nativeRole": "AXTextField", "identifier": "save", "enabled": true}}}
	g := newGatewayFixture(t, fixture, false)
	step := nativeStep("element.read")
	step.Effect.Class = model.ReadOnly
	step.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: "value"}}
	if _, err := g.Execute(ctx, p, step, nil); err == nil {
		t.Fatal("unapproved value read accepted")
	}
	for _, method := range fixture.calls {
		if method == "elements.read" {
			t.Fatal("value escaped policy gate")
		}
	}
	g.values["fixture.app"] = map[string]bool{"save": true}
	result, err := g.Execute(ctx, p, step, nil)
	if err != nil || result.Value == nil || result.Value.String != "literal ${data}" || result.VerificationState != "verified" {
		t.Fatalf("read: %+v %v", result, err)
	}
}
func TestGatewayDefaultNoMutationAndForgedScopes(t *testing.T) {
	ctx, p := nativeActor(t)
	fixture := &gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "ref", "nativeRole": "AXButton", "identifier": "save", "enabled": true}}}
	g := newGatewayFixture(t, fixture, true)
	if _, err := g.Execute(ctx, p, nativeStep("element.press"), nil); err == nil {
		t.Fatal("default mutation gate absent")
	}
	low, _ := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
	if _, err := g.Execute(auth.WithPrincipal(ctx, low), p, nativeStep("element.press"), nil); err == nil {
		t.Fatal("caller scopes overrode trusted context")
	}
}
