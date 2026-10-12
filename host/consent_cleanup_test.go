package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/session"
	"os"
	"testing"

	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
)

type cleanupProofCaller struct {
	inventory string
	inputHeld bool
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
		if c.inputHeld {
			result.Result = json.RawMessage(`{"released":false}`)
		}
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

func TestNativeConsentCleanupUsesHistoricalFenceWithoutStoppingChrome(t *testing.T) {
	for _, mode := range []string{"released", "helperAlive", "inputHeld", "foreignClient", "web", "chrome"} {
		t.Run(mode, func(t *testing.T) {
			f := newControlFixture(t)
			f.principal.ClientID = "fixture-agent"
			f.ctx = auth.WithPrincipal(context.Background(), f.principal)
			f.alive = mode == "helperAlive"
			lease := session.Lease{ID: "historical", Generation: 77, Owner: f.principal.Namespace, Scope: session.Scope{AllowedBundles: f.enrolled}}
			raw, _ := json.Marshal(map[string]any{"generation": 77, "lease": lease, "helper": f.identity, "inputProfile": "raw", "lastCleanup": session.CleanupReport{UnknownInputs: true, BusinessOutcomeUnknown: true}})
			if err := os.WriteFile(f.options.LockPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			factory := f.options.HelperFactory
			f.options.HelperFactory = func(c context.Context, o native.Options) (NativeControlHelper, error) {
				f.alive = true
				f.identity.StartToken = "new-helper"
				return factory(c, o)
			}
			h := &Host{users: map[string]User{f.principal.Namespace: {NativeBundles: f.enrolled}}}
			if err := h.configureNativeControl(f.owner, Config{NativeHelper: f.options.HelperPath}, HostOptions{NativeControl: &f.options}); err != nil {
				t.Fatal(err)
			}
			defer h.nativeControl.Close(context.Background())
			caller := &cleanupProofCaller{inventory: `{"complete":true,"apps":[{"bundleID":"com.google.Chrome"}]}`, inputHeld: mode == "inputHeld"}
			h.nativeClient = caller
			scope := consent.Scope{Kind: "application", BundleID: "com.fixture.app"}
			p := f.principal
			if mode == "web" {
				scope = consent.Scope{Kind: "origin", Origin: "https://fixture.invalid"}
			}
			if mode == "chrome" {
				scope = consent.Scope{Kind: "application", BundleID: "com.google.Chrome"}
			}
			if mode == "foreignClient" {
				p.ClientID = "foreign"
			}
			err := h.proveNativeConsentCleanup(f.ctx, p, scope)
			if (err == nil) != (mode == "released") {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
			for _, method := range caller.calls {
				if method != "doctor" && method != "input.releasedState" {
					t.Fatal("native proof touched browser", method)
				}
			}
			if mode == "released" && f.starts != 1 {
				t.Fatal("historical native fence was not independently recovered")
			}
			if mode != "released" && f.starts != 0 {
				t.Fatal("unproved fence created helper")
			}
		})
	}
}
