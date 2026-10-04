package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/script"
	"testing"
	"time"
)

type windowKeyFixture struct {
	calls  []string
	mode   string
	params map[string]any
	keys   int
}

func (*windowKeyFixture) Close() error { return nil }
func (f *windowKeyFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if e := ctx.Err(); e != nil {
		return Reply{}, e
	}
	f.calls = append(f.calls, r.Method)
	reply := Reply{RequestID: r.RequestID, HelperEpoch: "fixture"}
	switch r.Method {
	case "doctor":
		actions := []string{"pressSessionKey"}
		if f.mode == "noAdvert" {
			actions = nil
		}
		if f.mode == "unknownAdvert" {
			actions = []string{"pointerClick"}
		}
		body, _ := json.Marshal(map[string]any{"axTrusted": true, "semanticEnabled": true, "sessionKeyboardEnabled": f.mode != "noOptin", "nativeWindowActions": actions})
		reply.Result = body
	case "lease.install":
	case "windows.pressSessionKey":
		if r.Lease == nil || r.Lease.ID != "held" || r.Lease.Generation != 3 {
			panic("missing held window fence")
		}
		f.keys++
		json.Unmarshal(r.Params, &f.params)
		reply.Receipt = &Receipt{DispatchState: "dispatched", TargetRef: "window:9625"}
		proof := map[string]any{"pid": 1, "startToken": "100:1", "bundleID": "fixture.app", "windowId": 9625, "identity": "window:9625", "key": "Escape", "requestId": r.RequestID, "observedAt": time.Now(), "businessSuccess": false, "inputSemantics": "explicit login-session chord; global focus may change"}
		switch f.mode {
		case "wrongPID":
			proof["pid"] = 2
		case "wrongBirth":
			proof["startToken"] = "100:2"
		case "wrongBundle":
			proof["bundleID"] = "foreign.app"
		case "wrongWindow":
			proof["windowId"] = 1
		case "wrongIdentity":
			proof["identity"] = "window:1"
		case "wrongKey":
			proof["key"] = "Return"
		case "wrongRequest":
			proof["requestId"] = "foreign"
		case "businessClaim":
			proof["businessSuccess"] = true
		case "stale":
			proof["observedAt"] = time.Now().Add(-time.Minute)
		case "wrongReceipt":
			reply.Receipt.TargetRef = "window:1"
		case "missingResult":
			proof = map[string]any{}
		case "wrongEpoch":
			reply.HelperEpoch = "foreign"
		}
		reply.Result, _ = json.Marshal(proof)

		if f.mode == "noReceipt" {
			reply.Receipt = nil
		}
		if f.mode == "unknown" {
			return reply, &NativeError{Code: "windowUnconfirmed", DispatchState: "unknown"}
		}
	default:
		panic("AX or raw fallback: " + r.Method)
	}
	return reply, nil
}
func TestWindowKeyboardDirectCGRouteNoAXAndNoAutomaticVerification(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, mode := range []string{"valid", "noAdvert", "unknownAdvert", "noOptin", "noLease", "noReceipt", "unknown", "canceled", "wrongPID", "wrongBirth", "wrongBundle", "wrongWindow", "wrongIdentity", "wrongKey", "wrongRequest", "businessClaim", "stale", "wrongReceipt", "missingResult", "wrongEpoch"} {
		t.Run(mode, func(t *testing.T) {
			f := &windowKeyFixture{mode: mode}
			opts := GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "held", Generation: 3}, nil }}
			if mode == "noLease" {
				opts.Lease = nil
			}
			g, e := NewGateway(f, opts)
			if e != nil {
				t.Fatal(e)
			}
			plan, e := script.Compile(`app("fixture.app",processId:1,processStartToken:"100:1").pressWindowKey(windowId:9625,key:"Escape")`)
			if e != nil {
				t.Fatal(e)
			}
			local := ctx
			if mode == "canceled" {
				var cancel context.CancelFunc
				local, cancel = context.WithCancel(ctx)
				cancel()
			}
			r, e := g.Execute(local, p, plan.Steps[0], nil)
			if mode == "valid" {
				if e != nil || r.DispatchState != "dispatched" || r.VerificationState != "unknown" || f.keys != 1 {
					t.Fatal("direct route failed", r, e)
				}
			} else if mode != "noAdvert" && mode != "unknownAdvert" && mode != "noOptin" && mode != "noLease" && mode != "canceled" {
				if e == nil || r.DispatchState != "unknown" || f.keys != 1 {
					t.Fatal("ambiguous receipt inferredsuccess/absence", r, e)
				}
			} else if e == nil || r.DispatchState != "notDispatched" || f.keys != 0 {
				t.Fatal("unqualified keyboard dispatched", r, e)
			}
			if f.keys == 1 {
				if f.params["expectedApp"] != "fixture.app" || f.params["pid"] != float64(1) || f.params["processStartToken"] != "100:1" || f.params["windowId"] != float64(9625) || f.params["key"] != "Escape" {
					t.Fatal("exact window/process/key altered", f.params)
				}
			}
		})
	}
}

func TestWindowKeyTimestampQuantizationDoesNotCreateSpuriousUnknown(t *testing.T) {
	start := time.Date(2026, 10, 3, 15, 6, 40, 123900000, time.UTC)
	received := start.Add(50 * time.Microsecond)
	rounded := start.Round(time.Millisecond)
	if !rounded.After(received) || !windowKeyTimeQualified(rounded, start, received) {
		t.Fatal("valid millisecond rounding rejected")
	}
	for _, bad := range []time.Time{time.Time{}, start.Add(-2 * time.Millisecond), received.Add(2 * time.Millisecond), start.Add(-time.Minute)} {
		if windowKeyTimeQualified(bad, start, received) {
			t.Fatal("unqualified receipt time admitted")
		}
	}
	if windowKeyTimeQualified(start, start, received.Add(4*time.Second)) {
		t.Fatal("stale proof accepted")
	}
}
