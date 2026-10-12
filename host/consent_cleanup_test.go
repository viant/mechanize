package host

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
)

type cleanupProofCaller struct {
	inventory string
	calls     []string
}

func (c *cleanupProofCaller) Close() error { return nil }
func (c *cleanupProofCaller) Call(_ context.Context, r native.Request) (native.Reply, error) {
	c.calls = append(c.calls, r.Method)
	if r.Lease != nil {
		return native.Reply{}, errors.New("observation granted input")
	}
	result := native.Reply{HelperEpoch: "epoch"}
	switch r.Method {
	case "doctor":
	case "apps.list":
		result.Result = json.RawMessage(c.inventory)
	case "input.releasedState":
		result.Result = json.RawMessage(`{"released":true}`)
	default:
		return native.Reply{}, errors.New("unexpected observation")
	}
	return result, nil
}

func TestConsentCleanupRequiresStoppedChromeAndIndependentNativeFence(t *testing.T) {
	for _, tc := range []struct {
		name, inventory string
		ok              bool
	}{
		{"running browser", `{"complete":true,"apps":[{"bundleID":"com.google.Chrome"}]}`, false},
		{"incomplete inventory", `{"complete":false,"apps":[]}`, false},
		{"stopped browser", `{"complete":true,"apps":[]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newControlFixture(t)
			h := &Host{users: map[string]User{f.principal.Namespace: {NativeBundles: f.enrolled}}}
			if err := h.configureNativeControl(f.owner, Config{NativeHelper: f.options.HelperPath}, HostOptions{NativeControl: &f.options}); err != nil {
				t.Fatal(err)
			}
			defer h.nativeControl.Close(context.Background())
			caller := &cleanupProofCaller{inventory: tc.inventory}
			h.nativeClient = caller
			err := h.proveConsentCleanup(f.ctx, f.principal, consent.Scope{Kind: "desktop"})
			if (err == nil) != tc.ok {
				t.Fatalf("cleanup accepted=%v err=%v", tc.ok, err)
			}
			if !tc.ok && len(caller.calls) != 2 {
				t.Fatal("unconfirmed renderer lifecycle proceeded to native admission")
			}
		})
	}
}
