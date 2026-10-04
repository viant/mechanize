package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"testing"
)

type rootGatewayFixture struct {
	gatewayFixture
	advertised    []string
	echo          string
	partial       bool
	snapshotRoots []string
}

func (f *rootGatewayFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if r.Method == "doctor" {
		f.calls = append(f.calls, r.Method)
		raw, _ := json.Marshal(map[string]any{"axTrusted": true, "mutationEnabled": true, "nativeRootScopes": f.advertised})
		return Reply{HelperEpoch: "fixture", Result: raw}, nil
	}
	if r.Method == "elements.snapshot" {
		f.calls = append(f.calls, r.Method)
		var p map[string]any
		json.Unmarshal(r.Params, &p)
		root, _ := p["rootScope"].(string)
		f.snapshotRoots = append(f.snapshotRoots, root)
		if p["maxNodes"] != float64(1000) || p["maxDepth"] != float64(20) {
			panic("native root widened snapshot cap")
		}
		complete := root != "" && !f.partial
		raw, _ := json.Marshal(map[string]any{"observationId": "obs", "rootScope": f.echo, "generation": 1, "complete": complete, "truncated": !complete, "nodes": f.nodes})
		return Reply{HelperEpoch: "fixture", Result: raw}, nil
	}
	return f.gatewayFixture.Call(ctx, r)
}
func TestNativeRootLookupScopesBeforeSnapshotAndRequiresExactEcho(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, root := range []string{"menuBar", "focusedElement"} {
		for _, mode := range []string{"complete", "noAdvert", "wrongEcho", "noEcho", "partial", "wrongName", "duplicate"} {
			t.Run(root+"_"+mode, func(t *testing.T) {
				f := &rootGatewayFixture{gatewayFixture: gatewayFixture{mutation: true, nodes: []map[string]any{{"ref": "target", "nativeRole": "AXTextField", "name": "Go to the folder:", "enabled": true}}}, advertised: []string{root}, echo: root}
				switch mode {
				case "noAdvert":
					f.advertised = nil
				case "wrongEcho":
					f.echo = "other"
				case "noEcho":
					f.echo = ""
				case "partial":
					f.partial = true
				case "wrongName":
					f.nodes[0]["name"] = "Unrelated field"
				case "duplicate":
					f.nodes = append(f.nodes, f.nodes[0])
				}
				g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "desktop", Generation: 1}, nil }})
				if err != nil {
					t.Fatal(err)
				}
				plan, err := script.Compile(`app("fixture.app").` + root + `().getByRole("textbox", name: "Go to the folder:", exact: true).fill("/tmp")`)
				if err != nil {
					t.Fatal(err)
				}
				result, err := g.Execute(ctx, p, plan.Steps[0], nil)
				if mode == "complete" {
					if err != nil || result.DispatchState != "dispatched" {
						t.Fatalf("complete scoped lookup failed: %+v %v", result, err)
					}
					if len(f.snapshotRoots) != 1 || f.snapshotRoots[0] != root {
						t.Fatal("lookup traversed unscoped app before native root")
					}
				}
				if mode != "complete" {
					if err == nil {
						t.Fatal("invalid root lookup admitted input")
					}
					for _, call := range f.calls {
						if call == "elements.setValue" || call == "lease.install" {
							t.Fatal("rejected root scope reached mutation", call)
						}
					}
				}
				for _, cap := range g.Capabilities() {
					if cap.Name == map[string]string{"menuBar": "menuBarScope", "focusedElement": "focusedElementScope"}[root] && cap.Supported != (mode != "noAdvert") {
						t.Fatal("root capability did not follow advertisement")
					}
				}

			})
		}
	}
}

func TestNativeRootOrdinaryObservationRemainsWholeAppAndPartial(t *testing.T) {
	ctx, p := nativeActor(t)
	f := &rootGatewayFixture{advertised: []string{"menuBar", "focusedElement"}, gatewayFixture: gatewayFixture{nodes: []map[string]any{{"ref": "x", "nativeRole": "AXButton", "identifier": "save"}}}}
	g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := g.Observe(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"})
	if err != nil || !observation.Truncated || len(f.snapshotRoots) != 1 || f.snapshotRoots[0] != "" {
		t.Fatalf("ordinary observation changed scope/partial semantics: %+v %v", observation, err)
	}
}
