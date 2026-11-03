package darwin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/viant/mechanize/model"
)

type applicationLookupFixture struct {
	gatewayFixture
	version  int
	requests []Request
	failure  *NativeError
	gone     bool
}

func (f *applicationLookupFixture) Call(ctx context.Context, r Request) (Reply, error) {
	f.requests = append(f.requests, r)
	if r.Method == "app.lookup" || r.Method == "apps.list" {
		if r.Method == "app.lookup" && f.failure != nil {
			return Reply{}, f.failure
		}
		apps := []map[string]any{{"pid": 42, "bundleID": "fixture.app", "startToken": "1790000000:1", "launchTime": "kernel:1790000000:1"}}
		if f.gone {
			apps = nil
		}
		raw, _ := json.Marshal(map[string]any{"complete": true, "apps": apps})
		return Reply{HelperEpoch: "fixture", RequestID: r.RequestID, Result: raw}, nil
	}
	reply, err := f.gatewayFixture.Call(ctx, r)
	if r.Method == "doctor" {
		var result map[string]any
		_ = json.Unmarshal(reply.Result, &result)
		result["nativeApplicationLookupVersion"] = f.version
		reply.Result, _ = json.Marshal(result)
	}
	return reply, err
}
func TestPinnedObservationUsesAdvertisedExactApplicationLookup(t *testing.T) {
	for _, version := range []int{0, 1, 2} {
		f := &applicationLookupFixture{version: version, gatewayFixture: gatewayFixture{complete: true}}
		g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, p := nativeActor(t)
		surface := model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 42, ProcessStartToken: "1790000000:1"}
		if _, err = g.Observe(ctx, p, surface); err != nil {
			t.Fatal(err)
		}
		var query Request
		for _, r := range f.requests {
			if r.Method == "apps.list" || r.Method == "app.lookup" {
				query = r
			}
		}
		want := "apps.list"
		if version == 1 {
			want = "app.lookup"
		}
		if query.Method != want {
			t.Fatal("wrong compatibility route", query.Method, want)
		}
		if version == 1 {
			var args map[string]any
			_ = json.Unmarshal(query.Params, &args)
			if args["pid"] != float64(42) || args["startToken"] != surface.ProcessStartToken || args["launchTime"] != "kernel:"+surface.ProcessStartToken || len(args) != 4 {
				t.Fatal("exact identity lost")
			}
		}
	}
}
func TestMissingApplicationMetadataNeverProceedsToSnapshot(t *testing.T) {
	f := &applicationLookupFixture{version: 1, failure: &NativeError{Code: "incompleteObservation", DispatchState: "notDispatched"}}
	g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	ctx, p := nativeActor(t)
	_, err := g.Observe(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 42, ProcessStartToken: "1790000000:1"})
	if err == nil {
		t.Fatal("missing metadata accepted")
	}
	for _, r := range f.requests {
		if r.Method == "elements.snapshot" {
			t.Fatal("snapshot reached without app identity")
		}
	}
}
func TestKnownExitedPinnedProcessRemainsNotRunning(t *testing.T) {
	f := &applicationLookupFixture{version: 1, gone: true}
	g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	ctx, p := nativeActor(t)
	r, err := g.ProcessRunning(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 42, ProcessStartToken: "1790000000:1"})
	if err != nil || r.Running {
		t.Fatal("known exit lost", err)
	}
}
