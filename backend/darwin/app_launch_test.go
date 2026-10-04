package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type appLaunchFixture struct {
	calls          []Request
	enabled        bool
	launchReply    Reply
	launchErr      error
	observed       *Reply
	observationErr error
}

func (f *appLaunchFixture) Close() error { return nil }
func (f *appLaunchFixture) Call(ctx context.Context, request Request) (Reply, error) {
	f.calls = append(f.calls, request)
	reply := Reply{HelperEpoch: "fixture"}
	switch request.Method {
	case "doctor":
		reply.Result, _ = json.Marshal(map[string]any{"axTrusted": false, "mutationEnabled": false, "launchEnabled": f.enabled})
	case "apps.list":
		if f.observed != nil {
			return *f.observed, f.observationErr
		}
		reply.Result = json.RawMessage(`{"complete":true,"apps":[{"bundleID":"com.apple.mail","pid":42,"launchTime":"2026-10-01T00:00:00Z","startToken":"fixture-start"}]}`)
		return reply, f.observationErr
	case "app.launch":
		return f.launchReply, f.launchErr
	}
	return reply, nil
}
func appOpenStep() model.Step {
	return model.Step{ID: "launch", Action: "app.open", TimeoutMs: 1000, Effect: model.Effect{Class: model.ExternalNonIdempotent}, Target: model.Selector{Surface: model.Surface{Kind: "native", BundleID: "com.apple.mail"}, Cardinality: "one"}}
}
func TestAppLaunchDoesNotRequireAXOrClaimBusinessCompletion(t *testing.T) {
	ctx, p := nativeActor(t)
	fixture := &appLaunchFixture{enabled: true, launchReply: Reply{HelperEpoch: "fixture", Receipt: &Receipt{DispatchState: "dispatched"}, Result: json.RawMessage(`{"bundleID":"com.apple.mail","pid":42,"launchTime":"2026-10-01T00:00:00Z","startToken":"fixture-start","active":false}`)}}
	gateway, err := NewGateway(fixture, GatewayOptions{AllowedBundles: []string{"com.apple.mail"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "desktop", Generation: 1}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := gateway.Execute(ctx, p, appOpenStep(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.DispatchState != "dispatched" || result.VerificationState != "verified" || result.Value == nil || result.Value.Object["bundleID"].String != "com.apple.mail" {
		t.Fatalf("launch falsely verified: %+v", result)
	}
	if len(fixture.calls) != 4 || fixture.calls[3].Method != "apps.list" || fixture.calls[0].Method != "doctor" || fixture.calls[1].Method != "lease.install" || fixture.calls[2].Method != "app.launch" || fixture.calls[2].Lease == nil {
		t.Fatalf("unexpected launch route: %+v", fixture.calls)
	}
	var params map[string]any
	if json.Unmarshal(fixture.calls[2].Params, &params) != nil || len(params) != 1 || params["expectedApp"] != "com.apple.mail" {
		t.Fatalf("unsafe launch payload: %s", fixture.calls[2].Params)
	}
}
func TestAppLaunchFencesAndUnknownReceiptNeverRetry(t *testing.T) {
	cases := []struct {
		name      string
		enabled   bool
		fence     bool
		reply     Reply
		err       error
		wantCalls int
		wantState string
	}{
		{name: "disabled", fence: true, wantCalls: 1, wantState: "notDispatched"},
		{name: "no fence", enabled: true, wantCalls: 1, wantState: "notDispatched"},
		{name: "lost receipt", enabled: true, fence: true, err: &TransportError{Cause: errors.New("lost receipt"), DispatchState: "unknown"}, wantCalls: 3, wantState: "unknown"},
		{name: "wrong identity", enabled: true, fence: true, reply: Reply{Receipt: &Receipt{DispatchState: "dispatched"}, Result: json.RawMessage(`{"bundleID":"com.other.app","pid":42,"launchTime":"fixture"}`)}, wantCalls: 3, wantState: "unknown"},
		{name: "missing receipt", enabled: true, fence: true, reply: Reply{Result: json.RawMessage(`{"bundleID":"com.apple.mail","pid":42,"launchTime":"fixture"}`)}, wantCalls: 3, wantState: "unknown"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx, p := nativeActor(t)
			fixture := &appLaunchFixture{enabled: test.enabled, launchReply: test.reply, launchErr: test.err}
			options := GatewayOptions{AllowedBundles: []string{"com.apple.mail"}}
			if test.fence {
				options.Lease = func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "desktop", Generation: 1}, nil }
			}
			gateway, err := NewGateway(fixture, options)
			if err != nil {
				t.Fatal(err)
			}
			result, err := gateway.Execute(ctx, p, appOpenStep(), nil)
			if err == nil || result.DispatchState != test.wantState || len(fixture.calls) != test.wantCalls {
				t.Fatalf("launch result %+v err %v calls %+v", result, err, fixture.calls)
			}
		})
	}
}

func TestAppLaunchIndependentIdentityProofCannotBeForgedByReceipt(t *testing.T) {
	for _, test := range []struct {
		name     string
		observed Reply
		err      error
	}{
		{name: "PID reused", observed: Reply{Result: json.RawMessage(`{"complete":true,"apps":[{"bundleID":"com.apple.mail","pid":42,"launchTime":"2026-10-01T00:00:00Z","startToken":"different-process"}]}`)}},
		{name: "not running", observed: Reply{Result: json.RawMessage(`{"complete":true,"apps":[]}`)}},
		{name: "partial enumeration", observed: Reply{Result: json.RawMessage(`{"complete":false,"apps":[{"bundleID":"com.apple.mail","pid":42,"launchTime":"2026-10-01T00:00:00Z","startToken":"fixture-start"}]}`)}},
		{name: "lost independent observation", err: &TransportError{Cause: context.DeadlineExceeded, DispatchState: "unknown"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, p := nativeActor(t)
			fixture := &appLaunchFixture{enabled: true, launchReply: Reply{Receipt: &Receipt{DispatchState: "dispatched"}, Result: json.RawMessage(`{"bundleID":"com.apple.mail","pid":42,"launchTime":"2026-10-01T00:00:00Z","startToken":"fixture-start"}`)}, observed: &test.observed, observationErr: test.err}
			gateway, err := NewGateway(fixture, GatewayOptions{AllowedBundles: []string{"com.apple.mail"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "desktop", Generation: 1}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			result, err := gateway.Execute(ctx, p, appOpenStep(), nil)
			if err == nil || result.DispatchState != "unknown" || result.VerificationState != "unknown" || len(fixture.calls) != 4 {
				t.Fatalf("unproved effect %+v %v calls=%+v", result, err, fixture.calls)
			}
			launches := 0
			for _, request := range fixture.calls {
				if request.Method == "app.launch" {
					launches++
				}
			}
			if launches != 1 {
				t.Fatalf("launch replayed %d times", launches)
			}
		})
	}
}
