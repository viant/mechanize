package host

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"testing"
)

type releasedStateCaller struct {
	body  string
	epoch string
	calls []native.Request
}

func (c *releasedStateCaller) Close() error { return nil }
func (c *releasedStateCaller) Call(_ context.Context, r native.Request) (native.Reply, error) {
	c.calls = append(c.calls, r)
	if r.Method == "doctor" {
		return native.Reply{HelperEpoch: "epoch"}, nil
	}
	return native.Reply{HelperEpoch: c.epoch, Result: json.RawMessage(c.body)}, nil
}
func TestReleasedNativeInputProofAcceptsOnlyFreshClosedBooleanReply(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	p.ClientID = "agent"
	for _, tc := range []struct {
		body, epoch string
		ok          bool
	}{
		{`{"released":true}`, "epoch", true}, {`{"released":false}`, "epoch", false},
		{`{}`, "epoch", false}, {`{"released":"true"}`, "epoch", false},
		{`{"released":true,"keys":["SECRET-CANARY"]}`, "epoch", false},
		{`{"released":true} {}`, "epoch", false}, {`{"released":true}`, "stale", false},
	} {
		c := &releasedStateCaller{body: tc.body, epoch: tc.epoch}
		h := &Host{nativeClient: c}
		err := h.proveReleasedNativeInput(context.Background(), p)
		if (err == nil) != tc.ok {
			t.Fatalf("body %q accepted=%v", tc.body, err == nil)
		}
		if len(c.calls) != 2 || c.calls[1].Method != "input.releasedState" || c.calls[1].HelperEpoch != "epoch" || c.calls[1].Lease != nil || len(c.calls[1].Params) != 0 {
			t.Fatal("probe granted input or changed epoch")
		}
	}
}

func TestReleasedInputProofBindsBeforeObservationClientInitialization(t *testing.T) {
	f := newControlFixture(t)
	h := &Host{users: map[string]User{f.principal.Namespace: {NativeBundles: f.enrolled}}}
	if err := h.configureNativeControl(f.owner, Config{NativeHelper: f.options.HelperPath}, HostOptions{NativeControl: &f.options}); err != nil {
		t.Fatal(err)
	}
	defer h.nativeControl.Close(context.Background())
	if h.nativeControl.options.ReleasedInputProof == nil {
		t.Fatal("early Host construction silently disabled recovery")
	}
	c := &releasedStateCaller{body: `{"released":true}`, epoch: "epoch"}
	h.nativeClient = c
	if err := h.nativeControl.options.ReleasedInputProof(f.ctx, f.principal); err != nil || len(c.calls) != 2 {
		t.Fatal("late authenticated client not used", err)
	}
}
