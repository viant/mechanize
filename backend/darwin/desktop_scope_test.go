package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
)

type desktopLaunchFixture struct {
	current  string
	launches []Request
	installs int
}

func (f *desktopLaunchFixture) Close() error { return nil }
func (f *desktopLaunchFixture) Call(ctx context.Context, request Request) (Reply, error) {
	reply := Reply{HelperEpoch: "fixture"}
	switch request.Method {
	case "doctor":
		reply.Result = json.RawMessage(`{"launchEnabled":true,"axTrusted":false,"mutationEnabled":false}`)
	case "lease.install":
		f.installs++
	case "app.launch":
		var params struct {
			Expected string `json:"expectedApp"`
		}
		_ = json.Unmarshal(request.Params, &params)
		f.current = params.Expected
		f.launches = append(f.launches, request)
		reply.Receipt = &Receipt{DispatchState: "dispatched"}
		reply.Result, _ = json.Marshal(map[string]any{"bundleID": f.current, "pid": 42, "launchTime": "fixture", "startToken": "fixture-start"})
	case "apps.list":
		reply.Result, _ = json.Marshal(map[string]any{"complete": true, "apps": []map[string]any{{"bundleID": f.current, "pid": 42, "launchTime": "fixture", "startToken": "fixture-start"}}})
	}
	return reply, nil
}
func TestDesktopGatewayTargetsDifferentAppsWithOneGlobalFence(t *testing.T) {
	ctx, p := nativeActor(t)
	fixture := &desktopLaunchFixture{}
	gateway, err := NewGateway(fixture, GatewayOptions{AllApplications: true, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "desktop", Generation: 7}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, bundle := range []string{"com.apple.mail", "com.apple.TextEdit", "com.new.installation"} {
		step := appOpenStep()
		step.Target.Surface.BundleID = bundle
		result, err := gateway.Execute(ctx, p, step, nil)
		if err != nil || result.VerificationState != "verified" {
			t.Fatalf("desktop target %s %+v %v", bundle, result, err)
		}
	}
	if fixture.installs != 1 || len(fixture.launches) != 3 {
		t.Fatalf("perapp lease recreated installs=%d launches=%d", fixture.installs, len(fixture.launches))
	}
	for _, request := range fixture.launches {
		if request.Lease == nil || request.Lease.ID != "desktop" || request.Lease.Generation != 7 {
			t.Fatal("app changed desktop fence")
		}
	}
	for _, surface := range []model.Surface{{Kind: "native", BundleID: "*"}, {Kind: "native", BundleID: "/Applications/Mail.app"}, {Kind: "web", Origin: "https://example.test"}} {
		if err := gateway.surface(surface); err == nil {
			t.Fatalf("global native scope widened target %+v", surface)
		}
	}
	if _, err := NewGateway(fixture, GatewayOptions{AllApplications: true, AllowedBundles: []string{"com.apple.mail"}}); err == nil {
		t.Fatal("mixed fullandrestricted scope accepted")
	}
}
