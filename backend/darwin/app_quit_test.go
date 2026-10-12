package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type quitFixture struct {
	calls              []Request
	enabled            bool
	methods            []string
	inventoryComplete  bool
	duplicate          bool
	reply              Reply
	err                error
	exited             bool
	observeUnavailable bool
	wrongIdentity      bool
}

func (f *quitFixture) Close() error { return nil }
func (f *quitFixture) Call(_ context.Context, request Request) (Reply, error) {
	f.calls = append(f.calls, request)
	reply := Reply{HelperEpoch: "fixture"}
	switch request.Method {
	case "doctor":
		reply.Result, _ = json.Marshal(map[string]any{"quitEnabled": f.enabled, "supportedMethods": f.methods})
	case "apps.list":
		app := applicationIdentity{BundleID: "com.apple.mail", PID: 42, LaunchTime: "launch", StartToken: "start"}
		apps := []applicationIdentity{app}
		if f.duplicate {
			apps = append(apps, app)
		}
		reply.Result, _ = json.Marshal(map[string]any{"complete": f.inventoryComplete, "apps": apps})
	case "app.quit":
		f.reply.HelperEpoch = "fixture"
		return f.reply, f.err
	case "app.exitStatus":
		token := "start"
		if f.wrongIdentity {
			token = "other"
		}
		reply.Result, _ = json.Marshal(map[string]any{"bundleID": "com.apple.mail", "pid": 42, "launchTime": "launch", "startToken": token, "exitConfirmed": f.exited, "observationAvailable": !f.observeUnavailable})
	}
	return reply, nil
}
func TestQuitRequiresFeatureAuthorityAndIndependentExit(t *testing.T) {
	for _, name := range []string{"verified", "unsaved dialog", "not accepted", "missing receipt", "transport unknown", "transport not sent", "missing feature", "missing method", "incomplete inventory", "ambiguous target", "still running", "observation unavailable", "wrong identity", "missing exit proof", "no lease"} {
		t.Run(name, func(t *testing.T) {
			fixture := &quitFixture{enabled: true, methods: []string{"app.quit", "app.exitStatus"}, inventoryComplete: true, exited: true, reply: Reply{Receipt: &Receipt{DispatchState: "dispatched"}, Result: json.RawMessage(`{"bundleID":"com.apple.mail","pid":42,"launchTime":"launch","startToken":"start","quitRequested":true,"exitConfirmed":true}`)}}
			expectedDispatch := "unknown"
			expectedCalls := 1
			switch name {
			case "verified":
				expectedDispatch = "dispatched"
			case "unsaved dialog", "not accepted":
				fixture.reply.Receipt.DispatchState = "unknown"
				fixture.reply.Error = &NativeError{Code: "quitPostconditionUnknown", Message: "fixture", DispatchState: "unknown"}
			case "missing receipt":
				fixture.reply.Receipt = nil
			case "transport unknown":
				fixture.err = &TransportError{DispatchState: "unknown", Cause: errors.New("fixture")}
				fixture.reply = Reply{}
			case "transport not sent":
				fixture.err = &TransportError{DispatchState: "notDispatched", Cause: errors.New("fixture")}
				fixture.reply = Reply{}
				expectedDispatch = "notDispatched"
			case "missing feature":
				fixture.enabled = false
				expectedDispatch = "notDispatched"
				expectedCalls = 0
			case "missing method":
				fixture.methods = []string{"app.quit"}
				expectedDispatch = "notDispatched"
				expectedCalls = 0
			case "incomplete inventory":
				fixture.inventoryComplete = false
				expectedDispatch = "notDispatched"
				expectedCalls = 0
			case "ambiguous target":
				fixture.duplicate = true
				expectedDispatch = "notDispatched"
				expectedCalls = 0
			case "still running":
				fixture.exited = false
			case "observation unavailable":
				fixture.observeUnavailable = true
			case "wrong identity":
				fixture.wrongIdentity = true
			case "missing exit proof":
				fixture.reply.Result = json.RawMessage(`{}`)
			case "no lease":
				expectedDispatch = "notDispatched"
				expectedCalls = 0
			}
			options := GatewayOptions{AllowedBundles: []string{"com.apple.mail"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "desktop", Generation: 1}, nil }}
			if name == "no lease" {
				options.Lease = nil
			}
			gateway, err := NewGateway(fixture, options)
			if err != nil {
				t.Fatal(err)
			}
			ctx, p := nativeActor(t)
			step := appOpenStep()
			step.Action = "app.quit"
			step.Effect.BusinessKey = map[string]model.Value{"bundleID": {Kind: model.StringValue, String: "com.apple.mail"}}
			gateway.framePermit = &WindowFramePermit{}
			result, err := gateway.Execute(ctx, p, step, nil)
			if (err == nil) != (name == "verified") || result.DispatchState != expectedDispatch || (result.VerificationState == "verified") != (name == "verified") {
				t.Fatalf("result %+v error %v", result, err)
			}
			calls := 0
			for _, call := range fixture.calls {
				if call.Method == "app.quit" {
					calls++
					if call.Lease == nil {
						t.Fatal("unleased quit")
					}
				}
			}
			if calls != expectedCalls {
				t.Fatalf("quit called %d times, expected %d", calls, expectedCalls)
			}
			if calls > 0 && gateway.framePermit != nil {
				t.Fatal("lifecycle retained capture permit")
			}
		})
	}
}
