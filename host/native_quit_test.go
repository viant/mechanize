package host

import (
	"encoding/json"
	native "github.com/viant/mechanize/backend/darwin"
	"testing"
)

func TestNativeQuitRequiresControlScopeAndFence(t *testing.T) {
	for _, method := range []string{"app.quit", "app.exitStatus"} {
		for _, mode := range []string{"allowed", "semantic", "foreign scope", "missing lease", "wrong generation", "launch only"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				f := newControlFixture(t)
				if mode == "semantic" {
					f.manager.options.SemanticOnly = true
					f.ready.SemanticQualified = true
					f.ready.EventPost = false
					f.ready.MutationQualified = false
				}
				if mode == "launch only" {
					f.manager.options.LaunchOnly = true
					f.ready.LaunchQualified = true
				}
				f.admit(t)
				lease := native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}
				bundle := "com.fixture.app"
				if mode == "foreign scope" {
					bundle = "com.other.app"
				}
				params, _ := json.Marshal(map[string]any{"expectedApp": bundle, "pid": 42, "startToken": "1790000000:1", "launchTime": "kernel:1790000000:1"})
				request := native.Request{Method: method, Params: params}
				if method == "app.quit" {
					request.Lease = &lease
				}
				if mode == "missing lease" {
					request.Lease = nil
				}
				if mode == "wrong generation" {
					lease.Generation++
				}
				_, err := f.caller().Call(f.ctx, request)
				allowed := mode == "allowed" || mode == "semantic" || method == "app.exitStatus" && (mode == "missing lease" || mode == "wrong generation")
				if allowed && (err != nil || f.calls != 1) {
					t.Fatalf("allowed request rejected: %v, calls %d", err, f.calls)
				}
				if !allowed && (err == nil || f.calls != 0) {
					t.Fatalf("unqualified quit reached helper: %v, calls %d", err, f.calls)
				}
			})
		}
	}
}

func TestNativeQuitUnknownRetainsBarrier(t *testing.T) {
	f := newControlFixture(t)
	f.admit(t)
	f.callErr = &native.NativeError{Code: "quitPostconditionUnknown", Message: "fixture", DispatchState: "unknown"}
	request := mutation(f)
	request.Method = "app.quit"
	if _, err := f.caller().Call(f.ctx, request); err == nil {
		t.Fatal("unknown quit lost error")
	}
	if !f.manager.held.inhibited {
		t.Fatal("unknown quit did not inhibit control")
	}
	before := f.calls
	if _, err := f.caller().Call(f.ctx, request); err == nil {
		t.Fatal("unknown quit replayed")
	}
	if f.calls != before {
		t.Fatal("unknown quit reached helper again")
	}
}
