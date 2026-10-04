package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"testing"
)

func semanticFixture(t *testing.T) (*Host, *controlFixture) {
	h, f := hostControlFixture(t)
	f.manager.options.SemanticOnly = true
	f.ready.Unlocked = false
	f.ready.EventPost = false
	f.ready.MutationQualified = false
	f.ready.SemanticQualified = true
	f.ready.Accessibility = true
	return h, f
}
func TestDevelopmentSemanticProfileDoesNotManufactureUnlockedOrInputAuthority(t *testing.T) {
	h, f := semanticFixture(t)
	f.admit(t)
	policy, err := h.Policy(f.ctx, f.principal)
	if err != nil || !policy.Capabilities["native:semanticPress"] || !policy.Capabilities["native:semanticSubmit"] || !policy.Capabilities["native:replaceValue"] || policy.Capabilities["native:targetedKeyboard"] {
		t.Fatalf("profile %+v %v", policy, err)
	}
	lease := native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}
	for _, method := range []string{"input.key", "input.text", "input.pointer"} {
		if _, err := f.caller().Call(f.ctx, native.Request{Method: method, Lease: &lease, Params: json.RawMessage(`{"expectedApp":"com.fixture.app"}`)}); !errors.Is(err, auth.ErrUnauthorized) {
			t.Fatalf("raw input admitted %s: %v", method, err)
		}
	}
	if f.calls != 0 {
		t.Fatal("raw helper reached")
	}
	for _, method := range []string{"elements.press", "elements.setValue", "elements.submit"} {
		if _, err := f.caller().Call(f.ctx, native.Request{Method: method, Lease: &lease, Params: json.RawMessage(`{"expectedApp":"com.fixture.app"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if f.calls != 3 {
		t.Fatal("semantic dispatch missing")
	}
	f.ready.SecureInputEnabled = true
	if _, err := h.controlLeaseEpoch(f.ctx, f.principal); !errors.Is(err, ErrNativeControlUnqualified) {
		t.Fatalf("secure input admitted %v", err)
	}
}
func TestSemanticProfileRequiresExplicitReadinessAndExclusiveFactoryMode(t *testing.T) {
	for _, gate := range []string{"semantic", "AX"} {
		t.Run(gate, func(t *testing.T) {
			_, f := semanticFixture(t)
			if gate == "semantic" {
				f.ready.SemanticQualified = false
			} else {
				f.ready.Accessibility = false
			}
			if _, err := f.manager.Admit(f.ctx, f.principal, f.enrolled); !errors.Is(err, ErrNativeControlUnqualified) {
				t.Fatalf("gate admitted %v", err)
			}
		})
	}
	_, f := semanticFixture(t)
	f.options.SemanticOnly = true
	f.options.LaunchOnly = true
	if _, err := NewNativeControlManager(f.options); err == nil {
		t.Fatal("two authority profiles accepted")
	}
	f.manager.options.HelperFactory = func(ctx context.Context, options native.Options) (NativeControlHelper, error) {
		if !options.AllowSemantic || options.AllowMutations || options.AllowLaunch {
			t.Fatalf("wrong helper authority %+v", options)
		}
		return f, nil
	}
	f.admit(t)
}
