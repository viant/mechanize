package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/model"
	"testing"
)

type processFixture struct {
	apps           []applicationIdentity
	snapshotParams map[string]any
	calls          []string
}

func (f *processFixture) Close() error { return nil }
func (f *processFixture) Call(_ context.Context, r Request) (Reply, error) {
	f.calls = append(f.calls, r.Method)
	reply := Reply{HelperEpoch: "fixture"}
	var value any
	switch r.Method {
	case "doctor":
		value = map[string]any{"axTrusted": true}
	case "apps.list":
		value = map[string]any{"apps": f.apps, "complete": true}
	case "elements.snapshot":
		_ = json.Unmarshal(r.Params, &f.snapshotParams)
		value = map[string]any{"observationId": "obs", "generation": 1, "complete": true, "nodes": []any{}}
	}
	reply.Result, _ = json.Marshal(value)
	return reply, nil
}
func TestExactProcessSelectsOnlyMatchingFingerprint(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, test := range []struct {
		name  string
		pid   int
		token string
		code  string
	}{
		{"exact", 42, "1790000000:1", ""}, {"reused", 42, "1790000000:2", "staleReference"}, {"absent", 43, "1790000000:1", "staleReference"}, {"unqualified", 0, "", "ambiguousTarget"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := &processFixture{apps: []applicationIdentity{{BundleID: "fixture.app", PID: 41, LaunchTime: "a", StartToken: "1790000000:0"}, {BundleID: "fixture.app", PID: 42, LaunchTime: "b", StartToken: "1790000000:1"}}}
			g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
			if err != nil {
				t.Fatal(err)
			}
			s := model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: test.pid, ProcessStartToken: test.token}
			_, err = g.Observe(ctx, p, s)
			if test.code != "" {
				if e, ok := err.(*model.MechanizeError); !ok || e.Code != test.code {
					t.Fatalf("expected %s got %v", test.code, err)
				}
				if f.snapshotParams != nil {
					t.Fatal("snapshot dispatched for stale/ambiguous app")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if f.snapshotParams["pid"] != float64(42) || f.snapshotParams["processStartToken"] != "1790000000:1" {
				t.Fatalf("fingerprint not carried to helper: %+v", f.snapshotParams)
			}
		})
	}
}
