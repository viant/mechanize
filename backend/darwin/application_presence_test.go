package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/model"
)

type presenceFixture struct {
	mode  string
	calls []string
}

func (f *presenceFixture) Close() error { return nil }
func (f *presenceFixture) Call(_ context.Context, r Request) (Reply, error) {
	f.calls = append(f.calls, r.Method)
	if r.Method == "doctor" {
		return Reply{HelperEpoch: "fixture", Result: json.RawMessage(`{"nativeApplicationLookupVersion":1}`)}, nil
	}
	if r.Method != "apps.list" && r.Method != "app.lookup" {
		return Reply{}, errors.New("unexpected input or content read")
	}
	if f.mode == "offline" {
		return Reply{}, errors.New("unavailable")
	}
	app := map[string]any{"pid": 42, "bundleID": "com.example.Editor", "startToken": "100:1", "launchTime": "kernel:100:1"}
	apps := []any{app}
	if f.mode == "not-observed" {
		apps = []any{}
	}
	if f.mode == "ambiguous" {
		apps = append(apps, map[string]any{"pid": 43, "bundleID": "com.example.Editor", "startToken": "100:2", "launchTime": "kernel:100:2"})
	}
	if f.mode == "duplicate" {
		apps = append(apps, app)
	}
	if f.mode == "foreign" {
		app["bundleID"] = "com.example.Other"
	}
	if f.mode == "bad-birth" {
		app["startToken"] = "invalid"
	}
	if f.mode == "changed" && r.Method == "app.lookup" {
		app["startToken"] = "100:2"
		app["launchTime"] = "kernel:100:2"
	}
	raw := map[string]any{"complete": true, "apps": apps}
	if f.mode == "incomplete" {
		raw["complete"] = false
	}
	if f.mode == "missing" {
		delete(raw, "apps")
	}
	if f.mode == "null" {
		raw["apps"] = nil
	}
	data, _ := json.Marshal(raw)
	reply := Reply{HelperEpoch: "fixture", Result: data}
	if f.mode == "epoch" && r.Method == "app.lookup" {
		reply.HelperEpoch = "changed"
	}
	if f.mode == "receipt" {
		reply.Receipt = &Receipt{DispatchState: "dispatched"}
	}
	return reply, nil
}
func TestApplicationPresenceUsesReadOnlyCompleteScopedEvidence(t *testing.T) {
	for _, mode := range []string{"running", "not-observed", "ambiguous", "duplicate", "foreign", "bad-birth", "changed", "incomplete", "missing", "null", "epoch", "receipt", "offline"} {
		t.Run(mode, func(t *testing.T) {
			f := &presenceFixture{mode: mode}
			g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"com.example.Editor"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, p := nativeActor(t)
			v, err := g.ApplicationPresence(ctx, p, model.Surface{Kind: "native", BundleID: "com.example.Editor"})
			switch mode {
			case "running":
				if err != nil || v.State != "running" || v.ProcessID != 42 || v.ProcessStartToken != "100:1" || v.ObservedAt.IsZero() {
					t.Fatalf("running proof lost: %+v %v", v, err)
				}
			case "not-observed":
				if err != nil || v.State != "notObserved" || v.ProcessID != 0 {
					t.Fatalf("absence overstated: %+v %v", v, err)
				}
			case "ambiguous":
				if err != nil || v.State != "ambiguous" || v.ProcessID != 0 {
					t.Fatalf("ambiguous process selected: %+v %v", v, err)
				}
			default:
				if err == nil || v.State != "" {
					t.Fatalf("invalid evidence accepted: %+v", v)
				}
			}
			for _, method := range f.calls {
				if method != "doctor" && method != "apps.list" && method != "app.lookup" {
					t.Fatalf("unexpected call %s", method)
				}
			}
			if mode == "running" && (len(f.calls) != 3 || f.calls[2] != "app.lookup") {
				t.Fatal("missing independent pinned recheck", f.calls)
			}
		})
	}
}
func TestApplicationPresenceRejectsScopeBeforeCallingHelper(t *testing.T) {
	f := &presenceFixture{}
	g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"com.example.Editor"}})
	ctx, p := nativeActor(t)
	for _, s := range []model.Surface{{Kind: "web", Origin: "https://example.test"}, {Kind: "native", BundleID: "com.example.Other"}, {Kind: "native", BundleID: "com.example.Editor", ProcessID: 42, ProcessStartToken: "100:1"}} {
		if _, err := g.ApplicationPresence(ctx, p, s); err == nil {
			t.Fatal("invalid scope accepted")
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("denied scope reached helper")
	}
}
