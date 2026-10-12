package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"testing"
)

func TestSessionTextIsExplicitAndDoesNotEnableRawOrShortcutRoutes(t *testing.T) {
	h, f := semanticFixture(t)
	f.manager.options.SessionText = true
	f.ready.SessionTextQualified = true
	f.ready.EventPost = true
	f.manager.options.HelperFactory = func(ctx context.Context, options native.Options) (NativeControlHelper, error) {
		if !options.AllowSemantic || !options.AllowSessionText || options.AllowSessionKeyboard || options.AllowMutations {
			t.Fatal("text authority broadened")
		}
		return f, nil
	}
	f.admit(t)
	policy, err := h.Policy(f.ctx, f.principal)
	if err != nil || policy.Capabilities["native:windowSessionText"] {
		t.Fatal("text capability advertised without helper method evidence", err)
	}
	lease := native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}
	if _, err = f.caller().Call(f.ctx, native.Request{Method: "windows.typeText", Lease: &lease, Params: json.RawMessage(`{"expectedApp":"com.fixture.app"}`)}); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"windows.pressSessionKey", "elements.pressSessionKey", "input.text", "input.key", "input.pointer"} {
		if _, err = f.caller().Call(f.ctx, native.Request{Method: method, Lease: &lease, Params: json.RawMessage(`{"expectedApp":"com.fixture.app"}`)}); !errors.Is(err, auth.ErrUnauthorized) {
			t.Fatal("unrelated input route exposed", method, err)
		}
	}
	f.ready.SessionTextQualified = false
	if _, err = h.controlLeaseEpoch(f.ctx, f.principal); !errors.Is(err, ErrNativeControlUnqualified) {
		t.Fatal("lost text qualification retained authority", err)
	}
}
func TestSessionKeyboardDoesNotAuthorizeLiteralText(t *testing.T) {
	_, f := semanticFixture(t)
	f.manager.options.SessionKeyboard = true
	f.ready.SessionKeyboardQualified = true
	f.ready.EventPost = true
	f.admit(t)
	lease := native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}
	if _, err := f.caller().Call(f.ctx, native.Request{Method: "windows.typeText", Lease: &lease, Params: json.RawMessage(`{"expectedApp":"com.fixture.app"}`)}); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("shortcut enrollment admitted text", err)
	}
	if f.calls != 0 {
		t.Fatal("unenrolled text reached helper")
	}
}
