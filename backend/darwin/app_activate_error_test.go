package darwin

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type activationReadFailure struct {
	activationFixture
	failure       error
	failureMethod string
}

func (f *activationReadFailure) Call(ctx context.Context, q Request) (Reply, error) {
	if q.Method == f.failureMethod {
		f.calls = append(f.calls, q)
		return Reply{}, f.failure
	}
	return f.activationFixture.Call(ctx, q)
}
func TestActivationReadFailureKeepsOriginalErrorWithoutTypedNilPanic(t *testing.T) {
	for _, method := range []string{"apps.list", "app.activate"} {
		t.Run(method, func(t *testing.T) {
			ctx, p := nativeActor(t)
			original := &TransportError{Cause: errors.New("closed fixture transport"), DispatchState: "unknown"}
			caller := &activationReadFailure{failure: original, failureMethod: method}
			g, e := NewGateway(caller, GatewayOptions{AllowedBundles: []string{"com.apple.mail"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "desktop", Generation: 1}, nil }})
			if e != nil {
				t.Fatal(e)
			}
			step := appOpenStep()
			step.Action = "app.activate"
			step.Effect.BusinessKey = map[string]model.Value{"bundleID": {Kind: model.StringValue, String: "com.apple.mail"}}
			result, e := g.Execute(ctx, p, step, nil)
			expectedState := "notDispatched"
			expectedCalls := 0
			if method == "app.activate" {
				expectedState = "unknown"
				expectedCalls = 1
			}
			if e == nil || !errors.Is(e, original) || result.DispatchState != expectedState {
				t.Fatal("transport failure identity/uncertainty lost")
			}
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatal("original transport failure contains a typed-nil error")
				}
			}()
			_ = e.Error()
			sends := 0
			for _, q := range caller.calls {
				if q.Method == "app.activate" {
					sends++
				}
			}
			if sends != expectedCalls {
				t.Fatal("activation dispatch count changed", sends)
			}
		})
	}
}
