package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"testing"
)

type windowRootFixture struct {
	keyboardFixture
	mode      string
	selected  []map[string]string
	snapshots int
}

func (f *windowRootFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if r.Method == "doctor" {
		scopes := []string{"exactTitle"}
		if f.mode == "noAdvert" {
			scopes = nil
		}
		raw, _ := json.Marshal(map[string]any{"axTrusted": true, "semanticEnabled": true, "nativeWindowScopes": scopes})
		return Reply{HelperEpoch: "fixture", Result: raw}, nil
	}
	if r.Method == "elements.snapshot" {
		f.snapshots++
		var params struct {
			WindowScope map[string]string `json:"windowScope"`
			MaxNodes    int               `json:"maxNodes"`
			MaxDepth    int               `json:"maxDepth"`
		}
		json.Unmarshal(r.Params, &params)
		if params.MaxNodes != 1000 || params.MaxDepth != 20 {
			tpanic()
		}
		f.selected = append(f.selected, params.WindowScope)
		if f.mode == "ambiguous" {
			return Reply{}, &NativeError{Code: "ambiguousTarget", DispatchState: "notDispatched"}
		}
		echo := params.WindowScope
		if f.mode == "wrongEcho" {
			echo = map[string]string{"title": "Other"}
		}
		nodes := []map[string]any{{"ref": "window", "nativeRole": "AXWindow", "name": "Save"}, {"ref": "target", "parentRef": "window", "nativeRole": "AXPopUpButton", "name": "", "enabled": true, "focusSettable": true, "value": "PRIVATE_VALUE"}}
		raw, _ := json.Marshal(map[string]any{"observationId": "obs", "generation": 1, "windowScope": echo, "complete": f.mode != "partial", "truncated": f.mode == "partial" || len(params.WindowScope) == 0, "nodes": nodes})
		return Reply{HelperEpoch: "fixture", Result: raw}, nil
	}
	return f.keyboardFixture.Call(ctx, r)
}
func tpanic() { panic("window subtree raised global caps") }
func TestWindowRootScopesBeforeTraversalAndKeepsCompleteUniqueProof(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, mode := range []string{"complete", "noAdvert", "ambiguous", "wrongEcho", "partial"} {
		t.Run(mode, func(t *testing.T) {
			f := &windowRootFixture{mode: mode}
			g, e := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "held", Generation: 1}, nil }})
			if e != nil {
				t.Fatal(e)
			}
			plan, e := script.Compile(`app("fixture.app",processId:1,processStartToken:"100:1").window(title:"Save").getByRole("AXPopUpButton",name:"",exact:true).focus()`)
			if e != nil {
				t.Fatal(e)
			}
			result, e := g.Execute(ctx, p, plan.Steps[0], nil)
			if mode == "complete" {
				if e != nil || result.DispatchState != "dispatched" || result.Observation == nil || result.Observation.Truncated || result.Observation.WindowScope["title"] != "Save" || f.snapshots != 1 {
					t.Fatal("small selected subtree failed", result, e)
				}
			} else if e == nil {
				t.Fatal("invalidscope admittedinput", mode)
			}
			for _, request := range f.requests {
				if mode != "complete" && (request.Method == "elements.focus" || request.Method == "lease.install") {
					t.Fatal("invalidscope reachedinput/fence", request.Method)
				}
			}
			for _, scope := range f.selected {
				if scope["title"] != "Save" {
					t.Fatal("whole-app fallback", scope)
				}
			}
			if mode == "noAdvert" && f.snapshots != 0 {
				t.Fatal("unsupportedhelper reachedsnapshot")
			}
		})
	}
}
func TestWindowRootOrdinaryObservationRemainsWholeAppIncomplete(t *testing.T) {
	ctx, p := nativeActor(t)
	f := &windowRootFixture{}
	g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	obs, e := g.Observe(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"})
	if e != nil || !obs.Truncated || len(obs.WindowScope) != 0 {
		t.Fatal("wholeapp partialsemanticschanged", obs, e)
	}
}
