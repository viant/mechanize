package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
)

type activationFixture struct {
	calls      []Request
	active     bool
	disabled   bool
	incomplete bool
	duplicate  bool
	changed    bool
}

func (f *activationFixture) Close() error { return nil }
func (f *activationFixture) Call(_ context.Context, request Request) (Reply, error) {
	f.calls = append(f.calls, request)
	reply := Reply{HelperEpoch: "fixture"}
	switch request.Method {
	case "doctor":
		reply.Result, _ = json.Marshal(map[string]any{"axTrusted": true, "semanticEnabled": !f.disabled, "launchEnabled": true})
	case "apps.list":
		var params map[string]any
		_ = json.Unmarshal(request.Params, &params)
		if params["expectedApp"] != "com.apple.mail" {
			panic("unscoped inventory")
		}
		app := applicationIdentity{BundleID: "com.apple.mail", PID: 42, LaunchTime: "launch", StartToken: "start", Active: f.active}
		if f.changed && len(f.calls) > 3 {
			app.StartToken = "reused"
		}
		apps := []applicationIdentity{app}
		if f.duplicate {
			apps = append(apps, app)
		}
		reply.Result, _ = json.Marshal(map[string]any{"complete": !f.incomplete, "apps": apps})
	case "app.activate":
		reply.Receipt = &Receipt{DispatchState: "dispatched"}
	}
	return reply, nil
}
func TestActivationRequiresIndependentActiveIdentity(t *testing.T) {
	for _, test := range []struct {
		name     string
		fixture  activationFixture
		verified bool
	}{
		{"active", activationFixture{active: true}, true}, {"inactive", activationFixture{}, false}, {"reused", activationFixture{active: true, changed: true}, false}, {"unknown target", activationFixture{incomplete: true}, false}, {"duplicates", activationFixture{duplicate: true}, false}, {"launch only", activationFixture{disabled: true}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, p := nativeActor(t)
			fixture := test.fixture
			gateway, err := NewGateway(&fixture, GatewayOptions{AllowedBundles: []string{"com.apple.mail"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "desktop", Generation: 1}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			step := appOpenStep()
			step.Action = "app.activate"
			step.Effect.BusinessKey = map[string]model.Value{"bundleID": {Kind: model.StringValue, String: "com.apple.mail"}}
			result, err := gateway.Execute(ctx, p, step, nil)
			if test.verified {
				if err != nil || result.VerificationState != "verified" {
					t.Fatalf("%+v %v", result, err)
				}
			} else if err == nil || result.VerificationState == "verified" {
				t.Fatalf("false verification %+v %v", result, err)
			}
			dispatches := 0
			for _, call := range fixture.calls {
				if call.Method == "app.activate" {
					dispatches++
				}
			}
			if dispatches > 1 || (fixture.disabled || fixture.incomplete || fixture.duplicate) && dispatches != 0 {
				t.Fatalf("unexpected activation dispatch count %d", dispatches)
			}
		})
	}
}
