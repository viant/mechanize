package darwin

import (
	"encoding/json"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
)

func TestObserveNativeRootPreservesScopeAndWithholdsValues(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, root := range []string{"menuBar", "focusedElement"} {
		f := &rootGatewayFixture{advertised: []string{root}, echo: root, gatewayFixture: gatewayFixture{nodes: []map[string]any{{"ref": "x", "nativeRole": "AXTextField", "name": "Folder", "value": "PRIVATE_VALUE"}}}}
		g, e := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
		if e != nil {
			t.Fatal(e)
		}
		obs, e := g.ObserveNativeRoot(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"}, root)
		if e != nil || obs.NativeRoot != root || obs.Truncated || len(obs.Nodes) != 1 || len(f.snapshotRoots) != 1 || f.snapshotRoots[0] != root {
			t.Fatalf("scope lost: %+v %v", obs, e)
		}
		raw, _ := json.Marshal(obs)
		if strings.Contains(string(raw), "PRIVATE_VALUE") {
			t.Fatal("snapshot value exposed")
		}
		for _, call := range f.calls {
			if call != "doctor" && call != "apps.list" && call != "elements.snapshot" {
				t.Fatal("unexpected method", call)
			}
		}
	}
}
func TestObserveNativeRootNeverFallsBack(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, mode := range []string{"unknown", "empty", "web", "noAdvertisement", "badEcho", "noEcho", "unauthorized"} {
		t.Run(mode, func(t *testing.T) {
			root := "menuBar"
			surface := model.Surface{Kind: "native", BundleID: "fixture.app"}
			f := &rootGatewayFixture{advertised: []string{"menuBar"}, echo: "menuBar"}
			switch mode {
			case "unknown":
				root = "other"
			case "empty":
				root = ""
			case "web":
				surface = model.Surface{Kind: "web", Origin: "https://example.com"}
			case "noAdvertisement":
				f.advertised = nil
			case "badEcho":
				f.echo = "focusedElement"
			case "noEcho":
				f.echo = ""
			case "unauthorized":
				surface.BundleID = "foreign.app"
			}
			g, e := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = g.ObserveNativeRoot(ctx, p, surface, root); e == nil {
				t.Fatal("invalid scope accepted")
			}
			for _, actual := range f.snapshotRoots {
				if actual != "menuBar" {
					t.Fatal("scope broadened", actual)
				}
			}
			if mode == "noAdvertisement" && len(f.snapshotRoots) != 0 {
				t.Fatal("unsupported helper reached snapshot")
			}
		})
	}
}
