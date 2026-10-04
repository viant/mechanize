package darwin

import (
	"encoding/json"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
)

func TestActualAXOwnerMetadataPreservedWithoutAuthorityOrValues(t *testing.T) {
	ctx, p := nativeActor(t)
	f := &gatewayFixture{complete: true, nodes: []map[string]any{
		{"ref": "foreign", "nativeRole": "AXOutline", "identifier": "ListView", "enabled": true, "nativeOwnerProcessId": 77, "nativeOwnerStartToken": "100:1", "nativeOwnerUid": 501, "nativeOwnerBundleId": "com.apple.panel.fixture", "nativeOwnerMatchesRoot": false, "value": "private-fixture-content"},
		{"ref": "unknown", "nativeRole": "AXGroup", "unavailable": []string{"nativeOwnerProcessId", "nativeOwnerStartToken"}},
	}}
	g := newGatewayFixture(t, f, false)
	obs, e := g.Observe(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"})
	if e != nil {
		t.Fatal(e)
	}
	owner, unknown := obs.Nodes[0], obs.Nodes[1]
	if owner.NativeOwnerProcessID != 77 || owner.NativeOwnerStartToken != "100:1" || owner.NativeOwnerUID == nil || *owner.NativeOwnerUID != 501 || owner.NativeOwnerBundleID != "com.apple.panel.fixture" || owner.NativeOwnerMatchesRoot == nil || *owner.NativeOwnerMatchesRoot {
		t.Fatal("foreign same-UID AX owner lost")
	}
	if owner.Ref.AppLaunchID != "1:launch" {
		t.Fatal("diagnostic metadata changed root reference identity")
	}
	if unknown.NativeOwnerProcessID != 0 || unknown.NativeOwnerUID != nil || unknown.NativeOwnerMatchesRoot != nil || len(unknown.Unavailable) != 2 {
		t.Fatal("unknown owner inferred")
	}
	raw, _ := json.Marshal(obs)
	if strings.Contains(string(raw), "private-fixture-content") || len(owner.Values) != 0 {
		t.Fatal("owner metadata leaked values")
	}
	for _, cap := range g.Capabilities() {
		if (cap.Name == "targetedKeyboard" || cap.Name == "element.press") && cap.Supported {
			t.Fatal("metadata manufactured input authority")
		}
	}
}
