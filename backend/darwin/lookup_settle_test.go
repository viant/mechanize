package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type settlingLookupFixture struct {
	gatewayFixture
	mode                      string
	snapshots, inputs, leases int
	cancel                    context.CancelFunc
	t                         *testing.T
}

func (f *settlingLookupFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if r.Method == "elements.snapshot" {
		f.snapshots++
		var params map[string]any
		_ = json.Unmarshal(r.Params, &params)
		if params["processStartToken"] != "100:1" && f.mode != "unbound" {
			f.t.Fatal("lookup lost exact process birth")
		}
		f.complete = f.snapshots > 1 && f.mode != "persistent"
		f.nodes = []map[string]any{{"ref": fmt.Sprint("ref-", f.snapshots), "nativeRole": "AXButton", "identifier": "save", "enabled": true}}
		if f.mode == "ambiguous" {
			f.complete = true
			f.nodes = append(f.nodes, f.nodes[0])
		}
		if f.mode == "cancelled" {
			f.cancel()
		}
		if f.mode == "permission" {
			return Reply{}, nativeError("scopeDenied", "fixture denied")
		}
		if f.mode == "helper-transient" && f.snapshots == 1 {
			return Reply{}, &NativeError{Code: "rootUnavailable", Stage: "native", DispatchState: "notDispatched"}
		}
	}
	if r.Method == "lease.install" {
		f.leases++
	}
	if r.Method == "elements.press" {
		f.inputs++
		var params map[string]any
		_ = json.Unmarshal(r.Params, &params)
		if params["elementRef"] != fmt.Sprint("ref-", f.snapshots) {
			f.t.Fatal("input reused an incomplete snapshot reference")
		}
		if f.mode == "input-unknown" {
			return Reply{Receipt: &Receipt{DispatchState: "unknown"}}, &NativeError{Code: "nativeFailure", Stage: "native", DispatchState: "unknown"}
		}
	}
	reply, err := f.gatewayFixture.Call(ctx, r)
	if r.Method == "apps.list" {
		reply.Result, _ = json.Marshal(map[string]any{"complete": true, "apps": []map[string]any{{"pid": 1, "bundleID": "fixture.app", "launchTime": "launch", "startToken": "100:1"}}})
	}
	return reply, err
}

func TestInputLookupSettlesFreshReadsWithoutReplayingInput(t *testing.T) {
	for _, mode := range []string{"settle", "helper-transient", "persistent", "read", "unbound", "ambiguous", "permission", "cancelled", "deadline", "input-unknown"} {
		t.Run(mode, func(t *testing.T) {
			ctx, p := nativeActor(t)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			fixture := &settlingLookupFixture{gatewayFixture: gatewayFixture{mutation: true}, mode: mode, cancel: cancel, t: t}
			g, err := NewGateway(fixture, GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "desktop", Generation: 1}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			step := nativeStep("element.press")
			step.Target.Surface.ProcessID = 1
			step.Target.Surface.ProcessStartToken = "100:1"
			if mode == "deadline" {
				step.TimeoutMs = 20
			}
			if mode == "unbound" {
				step.Target.Surface.ProcessID = 0
				step.Target.Surface.ProcessStartToken = ""
			}
			if mode == "read" {
				step.Action = "element.read"
				step.Effect.Class = model.ReadOnly
				step.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: "name"}}
			}
			result, err := g.Execute(ctx, p, step, nil)
			if mode == "settle" || mode == "helper-transient" {
				if err != nil || fixture.snapshots != 2 || fixture.inputs != 1 || fixture.leases != 1 || result.DispatchState != "dispatched" {
					t.Fatalf("settle failed: %+v %v snapshots=%d inputs=%d", result, err, fixture.snapshots, fixture.inputs)
				}
			} else if mode == "input-unknown" {
				if err == nil || fixture.snapshots != 2 || fixture.inputs != 1 || result.DispatchState != "unknown" {
					t.Fatal("uncertain input repeated or relabeled")
				}
			} else {
				if mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("lookup escaped the original action deadline", err)
				}
				want := 1
				if mode == "persistent" {
					want = 3
				}
				if err == nil || fixture.snapshots != want || fixture.inputs != 0 || fixture.leases != 0 || result.DispatchState != "notDispatched" {
					t.Fatalf("unsafe %s: %+v %v snapshots=%d inputs=%d leases=%d", mode, result, err, fixture.snapshots, fixture.inputs, fixture.leases)
				}
			}
		})
	}
}

func TestLookupSettlingDoesNotAdmitIdentityTransportOrPolicyFailures(t *testing.T) {
	for _, err := range []error{
		&TransportError{Cause: nativeError("incompleteObservation", "fixture"), DispatchState: "unknown"},
		nativeError("staleReference", "fixture"), nativeError("ambiguousTarget", "fixture"),
		&NativeError{Code: "rootUnavailable", Stage: "native", DispatchState: "unknown"},
		&model.MechanizeError{Code: "targetNotFound", Stage: "policy", DispatchState: "notDispatched"},
		errors.New("incompleteObservation"),
	} {
		if transientLookupRead(err) {
			t.Fatalf("permanent error became transient: %T", err)
		}
	}
}
