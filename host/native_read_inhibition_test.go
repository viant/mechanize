package host

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	native "github.com/viant/mechanize/backend/darwin"
)

func TestPureNativeReadFailureDoesNotInventUnknownInput(t *testing.T) {
	for _, method := range []string{"doctor", "apps.list", "elements.snapshot", "elements.read", "elements.valueMatches", "windows.list", "app.exitStatus"} {
		t.Run(method, func(t *testing.T) {
			f := newControlFixture(t)
			f.admit(t)
			f.callErr = &native.TransportError{Cause: context.DeadlineExceeded, DispatchState: "unknown"}
			params, _ := json.Marshal(map[string]any{"expectedApp": "com.fixture.app", "bundleID": "com.fixture.app"})
			_, e := f.caller().Call(f.ctx, native.Request{Method: method, Params: params})
			if e == nil {
				t.Fatal("read transport failure hidden")
			}
			f.manager.mu.Lock()
			inhibited := f.manager.held == nil || f.manager.held.inhibited
			f.manager.mu.Unlock()
			if inhibited {
				t.Fatal("pure read created an unknown-input barrier")
			}
			f.callErr = nil
			if _, e = f.manager.Admit(f.ctx, f.principal, f.enrolled); e != nil {
				t.Fatal("read failure revoked valid control identity", e)
			}
		})
	}
}
func TestPureNativeReadCannotClearAlreadyInhibitedInput(t *testing.T) {
	f := newControlFixture(t)
	f.admit(t)
	f.manager.mu.Lock()
	f.manager.held.inhibited = true
	f.manager.mu.Unlock()
	if _, e := f.caller().Call(f.ctx, native.Request{Method: "doctor"}); e == nil {
		t.Fatal("read crossed original input barrier")
	}
	if f.calls != 0 {
		t.Fatal("inhibited read reached helper")
	}
	if _, e := f.manager.Admit(f.ctx, f.principal, f.enrolled); !errors.Is(e, ErrNativeControlCleanupUnknown) {
		t.Fatal("original unknown input was cleared", e)
	}
}
