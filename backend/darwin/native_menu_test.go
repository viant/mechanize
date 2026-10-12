package darwin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

type namedMenuFixture struct {
	gatewayFixture
	mode  string
	menus []string
}

func (f *namedMenuFixture) Call(ctx context.Context, r Request) (Reply, error) {
	reply := Reply{ProtocolVersion: 1, RequestID: r.RequestID, HelperEpoch: "fixture"}
	var value any
	switch r.Method {
	case "doctor":
		version := 1
		if f.mode == "unsupported" {
			version = 0
		}
		value = map[string]any{"axTrusted": true, "mutationEnabled": true, "nativeRootScopes": []string{"menuBar"}, "nativeMenuScopeVersion": version}
	case "apps.list":
		value = map[string]any{"complete": true, "apps": []any{map[string]any{"pid": 42, "bundleID": "fixture.app", "launchTime": "launch", "startToken": "100:1"}}}
	case "elements.snapshot":
		var params map[string]any
		_ = json.Unmarshal(r.Params, &params)
		menu, _ := params["nativeMenu"].(string)
		f.menus = append(f.menus, menu)
		nodes := []map[string]any{{"ref": "git", "nativeRole": "AXMenuBarItem", "name": "Git", "enabled": true}, {"ref": "push", "parentRef": "git", "nativeRole": "AXMenuItem", "name": "Push...", "enabled": true}}
		complete := menu == "Git"
		echo := menu
		if menu == "" {
			nodes = make([]map[string]any, 1000)
			for i := range nodes {
				nodes[i] = map[string]any{"ref": "unrelated", "nativeRole": "AXMenuItem", "name": "unrelated"}
			}
		}
		if f.mode == "wrongEcho" {
			echo = "Window"
		}
		if f.mode == "missingEcho" {
			echo = ""
		}
		if f.mode == "duplicate" {
			nodes = append(nodes, map[string]any{"ref": "duplicate", "parentRef": "git", "nativeRole": "AXMenuItem", "name": "Push...", "enabled": true})
		}
		value = map[string]any{"observationId": "obs", "generation": 1, "rootScope": "menuBar", "nativeMenu": echo, "complete": complete, "truncated": !complete, "nodes": nodes}
	default:
		return f.gatewayFixture.Call(ctx, r)
	}
	f.calls = append(f.calls, r.Method)
	reply.Result, _ = json.Marshal(value)
	return reply, nil
}
func TestNamedMenuBoundsLookupAndRejectsScopeEscapeBeforeInput(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, mode := range []string{"complete", "wrongEcho", "missingEcho", "duplicate", "unsupported"} {
		t.Run(mode, func(t *testing.T) {
			f := &namedMenuFixture{mode: mode}
			g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "lease", Generation: 1}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			surface := model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 42, ProcessStartToken: "100:1"}
			if mode == "complete" {
				whole, e := g.ObserveNativeRoot(ctx, p, surface, "menuBar")
				if e != nil || !whole.Truncated {
					t.Fatal("whole menu incorrectly complete", e)
				}
			}
			plan, e := script.Compile(`app("fixture.app",processId:42,processStartToken:"100:1").menuBar(name:"Git").getByRole("AXMenuItem",name:"Push...",exact:true).click()`)
			if e != nil {
				t.Fatal(e)
			}
			result, e := g.Execute(ctx, p, plan.Steps[0], nil)
			if mode == "complete" {
				if e != nil || result.DispatchState != "dispatched" {
					t.Fatal("small exact menu unavailable", result, e)
				}
				if len(f.menus) != 2 || f.menus[1] != "Git" {
					t.Fatal("scope not applied before traversal")
				}
			} else {
				if e == nil {
					t.Fatal("invalid menu scope dispatched")
				}
				for _, call := range f.calls {
					if call == "elements.press" || call == "lease.install" {
						t.Fatal("failed scope reached input authority")
					}
				}
			}
		})
	}
	target := nativeStep("element.press").Target
	target.Scope = model.Scope{NativeRoot: "menuBar", NativeMenu: "Git"}
	if _, err := resolve(model.Observation{NativeRoot: "menuBar", NativeMenu: "Window"}, target, nil); err == nil {
		t.Fatal("observation escaped named menu")
	}
}
