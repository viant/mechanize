package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/model"
	"testing"
)

type pinnedSnapshotFixture struct {
	applicationLookupFixture
	snapshotVersion int
	corrupt         string
	failure         *NativeError
}

func (f *pinnedSnapshotFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if r.Method == "elements.snapshot" && f.failure != nil {
		return Reply{}, f.failure
	}
	reply, err := f.applicationLookupFixture.Call(ctx, r)
	if err != nil {
		return reply, err
	}
	var result map[string]any
	_ = json.Unmarshal(reply.Result, &result)
	if r.Method == "doctor" {
		result["nativePinnedSnapshotVersion"] = f.snapshotVersion
	}
	if r.Method == "elements.snapshot" || r.Method == "windows.list" {
		if r.Method == "windows.list" {
			result["windowRootsOnly"] = true
			result["complete"] = true
			result["nodes"] = []any{}
		}
		result["pid"] = 42
		result["bundleID"] = "fixture.app"
		result["processStartToken"] = "1790000000:1"
		result["pinnedIdentityVerified"] = true
		switch f.corrupt {
		case "pid":
			result["pid"] = 43
		case "bundle":
			result["bundleID"] = "other.app"
		case "birth":
			result["processStartToken"] = "1790000000:2"
		case "proof":
			result["pinnedIdentityVerified"] = false
		case "missing":
			delete(result, "processStartToken")
		}
	}
	reply.Result, _ = json.Marshal(result)
	return reply, nil
}
func TestPinnedSnapshotRequiresQualifiedVersionAndExactProof(t *testing.T) {
	for _, version := range []int{0, 1, 2} {
		for _, corrupt := range []string{"", "pid", "bundle", "birth", "proof", "missing"} {
			f := &pinnedSnapshotFixture{applicationLookupFixture: applicationLookupFixture{version: 1, gatewayFixture: gatewayFixture{complete: true}}, snapshotVersion: version, corrupt: corrupt}
			g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
			ctx, p := nativeActor(t)
			_, err := g.Observe(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 42, ProcessStartToken: "1790000000:1"})
			if (err != nil) != (version == 1 && corrupt != "") {
				t.Fatalf("version %d corruption %s: %v", version, corrupt, err)
			}
			inventory, snapshots := 0, 0
			for _, r := range f.requests {
				if r.Method == "app.lookup" || r.Method == "apps.list" {
					inventory++
				}
				if r.Method == "elements.snapshot" {
					snapshots++
					var args map[string]any
					_ = json.Unmarshal(r.Params, &args)
					if (args["verifyPinnedIdentity"] == true) != (version == 1) {
						t.Fatal("wrong snapshot qualification")
					}
					if args["pid"] != float64(42) || args["processStartToken"] != "1790000000:1" {
						t.Fatal("lost exact identity")
					}
				}
			}
			want := 1
			if version == 1 {
				want = 0
			}
			if inventory != want || snapshots != 1 {
				t.Fatal("unexpected helper requests", inventory, snapshots)
			}
		}
	}
}
func TestPinnedSnapshotFailureDoesNotFallBackOrDispatch(t *testing.T) {
	f := &pinnedSnapshotFixture{applicationLookupFixture: applicationLookupFixture{version: 1, gatewayFixture: gatewayFixture{complete: true}}, snapshotVersion: 1, failure: &NativeError{Code: "incompleteObservation", DispatchState: "notDispatched"}}
	g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	ctx, p := nativeActor(t)
	_, err := g.Observe(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 42, ProcessStartToken: "1790000000:1"})
	if err == nil {
		t.Fatal("missing identity accepted")
	}
	for _, r := range f.requests {
		if r.Method != "doctor" {
			t.Fatal("failed snapshot retried or authority broadened", r.Method)
		}
	}
}
func TestUnpinnedSnapshotStillDiscoversApplication(t *testing.T) {
	f := &pinnedSnapshotFixture{applicationLookupFixture: applicationLookupFixture{version: 1, gatewayFixture: gatewayFixture{complete: true}}, snapshotVersion: 1}
	g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	ctx, p := nativeActor(t)
	if _, err := g.Observe(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range f.requests {
		if r.Method == "apps.list" {
			found = true
		}
		if r.Method == "elements.snapshot" {
			var args map[string]any
			_ = json.Unmarshal(r.Params, &args)
			if _, ok := args["verifyPinnedIdentity"]; ok {
				t.Fatal("unpinned request incorrectly qualified")
			}
		}
	}
	if !found {
		t.Fatal("discovery skipped")
	}
}

func TestPinnedWindowEnumerationUsesSameIdentityProof(t *testing.T) {
	for _, corrupt := range []string{"", "birth"} {
		f := &pinnedSnapshotFixture{applicationLookupFixture: applicationLookupFixture{version: 1, gatewayFixture: gatewayFixture{complete: true}}, snapshotVersion: 1, corrupt: corrupt}
		g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
		ctx, _ := nativeActor(t)
		_, err := g.observeSnapshot(ctx, model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 42, ProcessStartToken: "1790000000:1"}, "", true)
		if (err != nil) != (corrupt != "") {
			t.Fatalf("corruption %s: %v", corrupt, err)
		}
		for _, r := range f.requests {
			if r.Method == "app.lookup" || r.Method == "apps.list" {
				t.Fatal("redundant identity request")
			}
		}
	}
}
