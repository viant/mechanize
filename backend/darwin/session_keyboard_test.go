package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type sessionKeyboardFixture struct {
	keyboardFixture
	enabled bool
	fail    bool
}

func (f *sessionKeyboardFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if r.Method == "doctor" {
		f.requests = append(f.requests, r)
		b, _ := json.Marshal(map[string]any{"axTrusted": true, "semanticEnabled": true, "targetedKeyboardEnabled": true, "sessionKeyboardEnabled": f.enabled})
		return Reply{HelperEpoch: "fixture", Result: b}, nil
	}
	if r.Method == "elements.pressSessionKey" {
		f.requests = append(f.requests, r)
		if f.fail {
			return Reply{HelperEpoch: "fixture", Receipt: &Receipt{DispatchState: "unknown"}}, errors.New("lost session dispatch reply")
		}
		return Reply{HelperEpoch: "fixture", Receipt: &Receipt{DispatchState: "dispatched", TargetRef: "target"}}, nil
	}
	return f.keyboardFixture.Call(ctx, r)
}
func TestSessionKeyboardOptInAndNoFallback(t *testing.T) {
	for _, tc := range []struct {
		name          string
		enabled, fail bool
	}{{"disabled", false, false}, {"explicit", true, false}, {"uncertain", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, p := nativeActor(t)
			f := &sessionKeyboardFixture{enabled: tc.enabled, fail: tc.fail, keyboardFixture: keyboardFixture{gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "target", "nativeRole": "AXOutline", "identifier": "save", "enabled": true, "focused": true}}}}}
			g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "fixture", Generation: 1}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			s := nativeStep("element.pressSessionKey")
			s.Target.Surface.ProcessID = 1
			s.Target.Surface.ProcessStartToken = "100:1"
			s.Arguments = map[string]model.Value{"key": {Kind: model.StringValue, String: "Cmd+Shift+G"}}
			r, err := g.Execute(ctx, p, s, nil)
			if (!tc.enabled || tc.fail) != (err != nil) {
				t.Fatalf("unexpected result: %+v %v", r, err)
			}
			if !tc.enabled && r.DispatchState != "notDispatched" {
				t.Fatal("disabled route dispatched")
			}
			if tc.enabled && r.VerificationState == "verified" {
				t.Fatal("dispatch receipt became outcome verification")
			}
			n := 0
			for _, request := range f.requests {
				if request.Method == "elements.pressKey" {
					t.Fatal("fell back to process stream")
				}
				if request.Method == "elements.pressSessionKey" {
					n++
					if request.Lease == nil {
						t.Fatal("missing fence")
					}
				}
			}
			want := 0
			if tc.enabled {
				want = 1
			}
			if n != want {
				t.Fatalf("session dispatch count %d want %d", n, want)
			}
		})
	}
}
