package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"testing"
	"time"
)

type positionFixture struct {
	gatewayFixture
	mode     string
	attempts int
	params   map[string]any
}

func (f *positionFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if err := ctx.Err(); err != nil {
		return Reply{}, err
	}
	f.calls = append(f.calls, r.Method)
	reply := Reply{RequestID: r.RequestID, HelperEpoch: "fixture"}
	var out any
	switch r.Method {
	case "doctor":
		actions := []string{"setPosition"}
		if f.mode == "noAdvert" {
			actions = nil
		}
		if f.mode == "unknownAdvert" {
			actions = []string{"drag"}
		}
		out = map[string]any{"axTrusted": f.mode != "noAX", "semanticEnabled": f.mode != "noMutation", "nativeWindowActions": actions}
	case "apps.list":
		out = map[string]any{"complete": true, "apps": []map[string]any{{"pid": 1, "startToken": "1:2", "bundleID": "fixture.app", "launchTime": "launch"}}}
	case "windows.list":
		var p map[string]any
		json.Unmarshal(r.Params, &p)
		if p["maxDepth"] != float64(0) || p["pid"] != float64(1) || p["processStartToken"] != "1:2" {
			panic("invalid flat request")
		}
		role := "AXWindow"
		if f.mode == "wrongRole" {
			role = "AXButton"
		}
		nodes := []map[string]any{{"ref": "window", "nativeRole": role, "name": "Finder"}}
		if f.mode == "duplicate" {
			nodes = append(nodes, map[string]any{"ref": "second", "nativeRole": "AXWindow", "name": "Finder"})
		}
		if f.mode == "duplicateRef" {
			nodes = append(nodes, nodes[0])
		}
		out = map[string]any{"observationId": "obs", "generation": 1, "windowRootsOnly": f.mode != "noEcho", "complete": f.mode != "partial", "truncated": f.mode == "partial", "nodes": nodes, "startedAt": time.Now().Add(-time.Millisecond)}
	case "lease.install":
		out = map[string]any{}
	case "windows.setPosition":
		f.attempts++
		json.Unmarshal(r.Params, &f.params)
		reply.Receipt = &Receipt{DispatchState: "dispatched", TargetRef: "window"}
		x, y := 100, 100
		if f.mode == "mismatch" {
			x = 101
		}
		out = map[string]any{"positionVerified": f.mode != "unverified", "position": map[string]any{"x": x, "y": y}, "pid": 1, "startToken": "1:2", "bundleID": "fixture.app", "targetRef": "window", "generation": 1, "requestId": r.RequestID, "observedAt": time.Now()}
		switch f.mode {
		case "wrongBirth":
			out.(map[string]any)["startToken"] = "foreign"
		case "wrongRef":
			out.(map[string]any)["targetRef"] = "foreign"
		case "wrongGeneration":
			out.(map[string]any)["generation"] = 2
		case "wrongRequest":
			out.(map[string]any)["requestId"] = "foreign"
		case "staleProof":
			out.(map[string]any)["observedAt"] = time.Now().Add(-4 * time.Second)
		case "missingZero":
			out.(map[string]any)["position"] = map[string]any{"x": 100}
		case "noReceipt":
			reply.Receipt = nil
		case "wrongReceipt":
			reply.Receipt.TargetRef = "foreign"
		}
	default:
		panic("unexpected window route " + r.Method)
	}
	reply.Result, _ = json.Marshal(out)
	return reply, nil
}
func TestWindowPositionFencedFlatLookupAndExactReadback(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, mode := range []string{"valid", "noAdvert", "unknownAdvert", "noAX", "noMutation", "noLease", "wrongRole", "partial", "duplicate", "duplicateRef", "noEcho", "mismatch", "unverified", "wrongBirth", "wrongRef", "wrongGeneration", "wrongRequest", "staleProof", "missingZero", "noReceipt", "wrongReceipt"} {
		t.Run(mode, func(t *testing.T) {
			f := &positionFixture{mode: mode}
			opts := GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "held", Generation: 3}, nil }}
			if mode == "noLease" {
				opts.Lease = nil
			}
			g, e := NewGateway(f, opts)
			if e != nil {
				t.Fatal(e)
			}
			plan, e := script.Compile(`app("fixture.app",processId:1,processStartToken:"1:2").getByRole("window",name:"Finder",exact:true).moveTo({"x":100,"y":100})`)
			if e != nil {
				t.Fatal(e)
			}
			result, e := g.Execute(ctx, p, plan.Steps[0], nil)
			post := mode == "mismatch" || mode == "unverified" || mode == "wrongBirth" || mode == "wrongRef" || mode == "wrongGeneration" || mode == "wrongRequest" || mode == "staleProof" || mode == "missingZero" || mode == "noReceipt" || mode == "wrongReceipt"
			if mode == "valid" {
				if e != nil || result.DispatchState != "dispatched" || result.VerificationState != "verified" || f.attempts != 1 || result.Observation == nil || !result.Observation.WindowRootsOnly {
					t.Fatalf("window move failed %+v %v", result, e)
				}
				position := f.params["position"].(map[string]any)
				if len(position) != 2 || position["x"] != float64(100) || position["y"] != float64(100) {
					t.Fatal("position changed")
				}
			} else if post {
				if e == nil || result.DispatchState != "unknown" || result.VerificationState == "verified" || f.attempts != 1 {
					t.Fatalf("unproven move misreported %+v %v", result, e)
				}
			} else {
				if e == nil || f.attempts != 0 || result.DispatchState != "notDispatched" {
					t.Fatalf("invalid move dispatched %+v %v", result, e)
				}
			}
			for _, call := range f.calls {
				if call == "elements.snapshot" || call == "input.pointer" || call == "elements.press" {
					t.Fatal("unexpected fallback", call)
				}
			}
			if f.attempts > 1 {
				t.Fatal("mutation retried")
			}
			caps := g.Capabilities()
			found := false
			for _, c := range caps {
				if c.Name == "windowPosition" {
					found = true
					want := mode != "noAdvert" && mode != "unknownAdvert" && mode != "noAX" && mode != "noMutation" && mode != "noLease"
					if c.Supported != want {
						t.Fatal("capability ignored readiness", mode, c)
					}
				}
			}
			if !found {
				t.Fatal("window capability missing")
			}
		})
	}
}
func TestWindowPositionBadBoundInputsAvoidDispatch(t *testing.T) {
	ctx, p := nativeActor(t)
	f := &positionFixture{}
	g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	plan, _ := script.Compile(`app("fixture.app",processId:1,processStartToken:"1:2").getByRole("window").moveTo({"x":100,"y":100})`)
	s := plan.Steps[0]
	s.Arguments["position"] = model.Value{Kind: model.ReferenceValue, Expected: model.ObjectValue, Ref: "input.position"}
	if _, e := g.Execute(ctx, p, s, map[string]model.Value{"input.position": {Kind: model.ObjectValue, Object: map[string]model.Value{"x": {Kind: model.NumberValue, Number: 32768}, "y": {Kind: model.NumberValue}}}}); e == nil {
		t.Fatal("invalid reference accepted")
	}
	if len(f.calls) != 0 {
		t.Fatal("invalid argument reached helper")
	}
}

func TestWindowPositionCanceledContextAvoidsDispatch(t *testing.T) {
	ctx, p := nativeActor(t)
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	f := &positionFixture{}
	g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	plan, e := script.Compile(`app("fixture.app",processId:1,processStartToken:"1:2").getByRole("window").moveTo({"x":100,"y":100})`)
	if e != nil {
		t.Fatal(e)
	}
	result, e := g.Execute(ctx, p, plan.Steps[0], nil)
	if e == nil || f.attempts != 0 || len(f.calls) != 0 || result.DispatchState != "notDispatched" {
		t.Fatalf("canceled action dispatched %+v %v", result, e)
	}
}
