package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/session"
)

func TestNativeControlUnknownApplicationFailureInhibitsFurtherInput(t *testing.T) {
	for _, method := range []string{"elements.press", "elements.focus", "elements.setValue", "elements.submit", "elements.showMenu", "elements.replaceText", "windows.setPosition", "windows.pressSessionKey", "windows.typeText", "elements.pressSessionKey", "app.activate", "app.launch", "app.quit"} {
		for _, dispatch := range []string{"unknown", "notDispatched"} {
			t.Run(method+"/"+dispatch, func(t *testing.T) {
				f := newControlFixture(t)
				f.manager.options.SessionKeyboard = true
				f.manager.options.SessionText = true
				f.admit(t)
				failure := &native.NativeError{Code: "fixtureFailure", DispatchState: dispatch}
				f.callErr = fmt.Errorf("wrapped helper failure: %w", failure)
				request := mutation(f)
				request.Method = method
				_, err := f.caller().Call(f.ctx, request)
				if !errors.Is(err, failure) || f.calls != 1 {
					t.Fatal("helper failure was not preserved", err, f.calls)
				}
				wantInhibited := dispatch == "unknown"
				if f.manager.held.inhibited != wantInhibited {
					t.Fatalf("inhibited = %v, want %v", f.manager.held.inhibited, wantInhibited)
				}
				if wantInhibited {
					data, readErr := os.ReadFile(f.options.LockPath)
					if readErr != nil {
						t.Fatal(readErr)
					}
					var state struct {
						LastCleanup *session.CleanupReport `json:"lastCleanup"`
					}
					if err := json.Unmarshal(data, &state); err != nil || state.LastCleanup == nil || !state.LastCleanup.UnknownInputs || !state.LastCleanup.InputInhibited {
						t.Fatal("uncertainty was not persisted before returning", err)
					}
				}
				f.callErr = nil
				_, err = f.caller().Call(f.ctx, mutation(f))
				if wantInhibited {
					if err == nil || f.calls != 1 {
						t.Fatal("uncertain action allowed subsequent input", err, f.calls)
					}
				} else if err != nil || f.calls != 2 {
					t.Fatal("undispatched failure unnecessarily blocked input", err, f.calls)
				}
			})
		}
	}
}

func TestNativeControlUnknownReadFailureDoesNotInhibitInput(t *testing.T) {
	f := newControlFixture(t)
	f.admit(t)
	f.callErr = &native.NativeError{Code: "fixtureReadFailure", DispatchState: "unknown"}
	request := mutation(f)
	request.Method = "elements.read"
	if _, err := f.caller().Call(f.ctx, request); err == nil || f.calls != 1 || f.manager.held.inhibited {
		t.Fatal("read failure changed input authority", err, f.calls)
	}
	f.callErr = nil
	if _, err := f.caller().Call(f.ctx, mutation(f)); err != nil || f.calls != 2 {
		t.Fatal("read failure blocked fresh qualified input", err, f.calls)
	}
}
