package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"testing"
)

type menuFixture struct {
	gatewayFixture
	advertised bool
	menus      int
}

func (f *menuFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if r.Method == "doctor" {
		actions := []string{}
		if f.advertised {
			actions = append(actions, "AXShowMenu")
		}
		b, _ := json.Marshal(map[string]any{"axTrusted": true, "semanticEnabled": true, "nativeSemanticMenus": actions})
		return Reply{HelperEpoch: "fixture", Result: b}, nil
	}
	if r.Method == "apps.list" {
		return Reply{HelperEpoch: "fixture", Result: json.RawMessage(`{"complete":true,"apps":[{"pid":1,"bundleID":"fixture.app","launchTime":"launch","startToken":"100:1"}]}`)}, nil
	}
	if r.Method == "elements.showMenu" {
		f.calls = append(f.calls, r.Method)
		f.menus++
		if r.Lease == nil || r.Lease.ID != "desktop" {
			t := &NativeError{Code: "missingFence", DispatchState: "notDispatched"}
			return Reply{}, t
		}
		return Reply{HelperEpoch: "fixture", Receipt: &Receipt{DispatchState: "dispatched"}}, nil
	}
	return f.gatewayFixture.Call(ctx, r)
}
func TestShowMenuRequiresExactMenuActionAndDoesNotPress(t *testing.T) {
	for _, mode := range []string{"menu", "popup", "oldHelper", "pressOnly", "wrongRole", "disabled", "missingEnabled", "missingProcess", "wrongBirth", "noLease", "observeOnly"} {
		t.Run(mode, func(t *testing.T) {
			ctx, p := nativeActor(t)
			node := map[string]any{"ref": "menu", "identifier": "save", "nativeRole": "AXMenuButton", "enabled": true, "actions": []string{"AXPress", "AXShowMenu"}}
			f := &menuFixture{advertised: mode != "oldHelper", gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{node}}}
			switch mode {
			case "popup":
				node["nativeRole"] = "AXPopUpButton"
			case "pressOnly":
				node["actions"] = []string{"AXPress"}
			case "wrongRole":
				node["nativeRole"] = "AXTextField"
			case "disabled":
				node["enabled"] = false
			case "missingEnabled":
				delete(node, "enabled")
			case "observeOnly":
				p, _ = auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
				ctx = auth.WithPrincipal(context.Background(), p)
			}
			opts := GatewayOptions{AllowedBundles: []string{"fixture.app"}}
			if mode != "noLease" {
				opts.Lease = func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "desktop", Generation: 1}, nil }
			}
			g, err := NewGateway(f, opts)
			if err != nil {
				t.Fatal(err)
			}
			step := nativeStep("element.showMenu")
			step.Target.Surface.ProcessID = 1
			step.Target.Surface.ProcessStartToken = "100:1"
			if mode == "missingProcess" {
				step.Target.Surface.ProcessID = 0
				step.Target.Surface.ProcessStartToken = ""
			}
			if mode == "wrongBirth" {
				step.Target.Surface.ProcessStartToken = "100:2"
			}
			result, err := g.Execute(ctx, p, step, nil)
			want := mode == "menu" || mode == "popup"
			if want {
				if err != nil || result.DispatchState != "dispatched" || result.VerificationState != "unknown" || f.menus != 1 {
					t.Fatalf("qualified menu %+v %v menus=%d", result, err, f.menus)
				}
			} else if err == nil || result.DispatchState != "notDispatched" || f.menus != 0 {
				t.Fatalf("unqualified menu %+v %v menus=%d", result, err, f.menus)
			}
			for _, method := range f.calls {
				if method == "elements.press" || method == "elements.pressKey" || method == "input.key" {
					t.Fatal("menu disclosure substituted another input")
				}
			}
			f.advertised = false
			g.epoch = ""
			if err := g.ready(ctx); err != nil {
				t.Fatal(err)
			}
			if g.semanticMenuEnabled {
				t.Fatal("replacement helper retained menu capability")
			}
		})
	}
}
