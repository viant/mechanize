package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"os"
	"testing"
)

func TestSessionKeyboardCompositeKeepsSemanticActionsAndRejectsOtherRoutes(t *testing.T) {
	h, f := semanticFixture(t)
	f.manager.options.SessionKeyboard = true
	f.ready.SessionKeyboardQualified = true
	f.ready.EventPost = true
	f.manager.options.HelperFactory = func(ctx context.Context, options native.Options) (NativeControlHelper, error) {
		if !options.AllowSemantic || !options.AllowSessionKeyboard || options.AllowMutations || options.AllowLaunch {
			t.Fatal("keyboard composite broadened to raw input")
		}
		return f, nil
	}
	f.admit(t)
	policy, err := h.Policy(f.ctx, f.principal)
	if err != nil || !policy.Capabilities["native:sessionKeyboard"] || !policy.Capabilities["native:semanticPress"] || !policy.Capabilities["native:targetedFocus"] {
		t.Fatalf("composite capabilities: %v", err)
	}
	bytes, err := os.ReadFile(f.options.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	json.Unmarshal(bytes, &record)
	if record["inputProfile"] != "raw" {
		t.Fatal("keyboard posting incorrectly classified as semantic-only cleanup")
	}
	lease := native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}
	for _, method := range []string{"elements.focus", "elements.pressSessionKey", "elements.press", "elements.setValue", "elements.submit"} {
		if _, err = f.caller().Call(f.ctx, native.Request{Method: method, Lease: &lease, Params: json.RawMessage(`{"expectedApp":"com.fixture.app"}`)}); err != nil {
			t.Fatal("composite typed method blocked", method, err)
		}
	}
	for _, method := range []string{"elements.pressKey", "input.key", "input.text", "input.pointer"} {
		if _, err = f.caller().Call(f.ctx, native.Request{Method: method, Lease: &lease, Params: json.RawMessage(`{"expectedApp":"com.fixture.app"}`)}); !errors.Is(err, auth.ErrUnauthorized) {
			t.Fatal("raw route exposed")
		}
	}
	f.ready.EventPost = false
	if _, err = h.controlLeaseEpoch(f.ctx, f.principal); !errors.Is(err, ErrNativeControlUnqualified) {
		t.Fatal("revoked posting permission retained authority")
	}
}
func TestSessionKeyboardProfileRequiresReadinessAndExactLease(t *testing.T) {
	for _, missing := range []string{"keyboard", "eventPost", "AX", "session", "secure"} {
		t.Run(missing, func(t *testing.T) {
			_, f := semanticFixture(t)
			f.manager.options.SessionKeyboard = true
			f.ready.SessionKeyboardQualified = true
			f.ready.EventPost = true
			switch missing {
			case "keyboard":
				f.ready.SessionKeyboardQualified = false
			case "eventPost":
				f.ready.EventPost = false
			case "AX":
				f.ready.Accessibility = false
			case "session":
				f.ready.ActiveGraphicalSession = false
			case "secure":
				f.ready.SecureInputEnabled = true
			}
			if _, err := f.manager.Admit(f.ctx, f.principal, f.enrolled); !errors.Is(err, ErrNativeControlUnqualified) {
				t.Fatal("unqualified keyboard profile admitted")
			}
		})
	}
	_, f := semanticFixture(t)
	f.manager.options.SessionKeyboard = true
	f.ready.SessionKeyboardQualified = true
	f.ready.EventPost = true
	f.admit(t)
	wrong := native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation + 1}
	if _, err := f.caller().Call(f.ctx, native.Request{Method: "elements.pressSessionKey", Lease: &wrong, Params: json.RawMessage(`{"expectedApp":"com.fixture.app"}`)}); err == nil || f.calls != 0 {
		t.Fatal("foreign key lease dispatched")
	}
}
