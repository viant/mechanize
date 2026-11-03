package host

import (
	"encoding/json"
	"errors"
	"testing"

	native "github.com/viant/mechanize/backend/darwin"
)

func TestNativeApplicationLookupRetainsScopeWithoutInputAuthority(t *testing.T) {
	for _, mode := range []string{"allowed", "foreign", "missing", "launch-only", "transport"} {
		t.Run(mode, func(t *testing.T) {
			f := newControlFixture(t)
			if mode == "launch-only" {
				f.manager.options.LaunchOnly = true
				f.ready.LaunchQualified = true
			}
			f.admit(t)
			request := native.Request{Method: "app.lookup", Params: json.RawMessage(`{"expectedApp":"com.fixture.app","pid":42,"startToken":"1790000000:1","launchTime":"kernel:1790000000:1"}`)}
			if mode == "foreign" {
				request.Params = json.RawMessage(`{"expectedApp":"com.foreign.app"}`)
			}
			if mode == "missing" {
				request.Params = json.RawMessage(`{}`)
			}
			if mode == "transport" {
				f.callErr = &native.TransportError{Cause: errors.New("fixture read unavailable"), DispatchState: "unknown"}
			}
			_, err := f.caller().Call(f.ctx, request)
			if mode == "foreign" || mode == "missing" {
				if err == nil || f.calls != 0 {
					t.Fatal("lookup escaped application scope", err)
				}
			} else {
				if f.calls != 1 || (err != nil) != (mode == "transport") {
					t.Fatal("unexpected lookup result", err, f.calls)
				}
			}
			if f.manager.held.inhibited {
				t.Fatal("read-only lookup created an input-uncertainty barrier")
			}
		})
	}
}
