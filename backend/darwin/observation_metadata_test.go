package darwin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mechanize/model"
)

func TestGatewayPropagatesAdvertisedAXMetadataWithoutProtectedValues(t *testing.T) {
	ctx, p := nativeActor(t)
	fixture := &gatewayFixture{complete: true, nodes: []map[string]any{
		{"ref": "press", "nativeRole": "AXButton", "name": "Select", "enabled": true, "actions": []string{"AXPress", "AXShowMenu"}, "valueSettable": false},
		{"ref": "field", "nativeRole": "AXTextField", "subrole": "AXSecureTextField", "name": "Protected field", "enabled": true, "actions": []string{"AXConfirm"}, "valueSettable": true, "value": "fixture-protected-value", "values": map[string]string{"value": "fixture-protected-value"}, "valueUnavailable": "withheldByPolicy"},
		{"ref": "unknown", "nativeRole": "AXGroup", "name": "Group", "enabled": true},
	}}
	g := newGatewayFixture(t, fixture, false)
	observation, err := g.Observe(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Nodes) != 3 {
		t.Fatal("helper payload nodes not propagated")
	}
	button, field, unknown := observation.Nodes[0], observation.Nodes[1], observation.Nodes[2]
	if len(button.Actions) != 2 || button.Actions[0] != "AXPress" || button.Actions[1] != "AXShowMenu" || button.ValueSettable == nil || *button.ValueSettable {
		t.Fatal("button advertised metadata lost or changed")
	}
	if len(field.Actions) != 1 || field.Actions[0] != "AXConfirm" || field.ValueSettable == nil || !*field.ValueSettable {
		t.Fatal("field advertised metadata lost")
	}
	if unknown.ValueSettable != nil || len(unknown.Actions) != 0 {
		t.Fatal("missing helper metadata guessed")
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "fixture-protected-value") || len(field.Values) != 0 {
		t.Fatal("protected/editable value leaked from helper payload")
	}
	if !strings.Contains(string(raw), `"valueSettable":false`) || !strings.Contains(string(raw), `"actions":["AXPress","AXShowMenu"]`) {
		t.Fatal("metadata absent from actual observation JSON")
	}
	for _, cap := range g.Capabilities() {
		if (cap.Name == "element.press" || cap.Name == "element.fill" || cap.Name == "element.submit") && cap.Supported {
			t.Fatal("advertised actions manufactured authorization")
		}
	}
	for _, call := range fixture.calls {
		if call == "lease.install" || strings.HasPrefix(call, "input.") || call == "elements.press" || call == "elements.setValue" || call == "elements.submit" {
			t.Fatal("observation acquired or dispatched input")
		}
	}
}
func TestGatewayBoundsAdvertisedAXActionMetadata(t *testing.T) {
	ctx, p := nativeActor(t)
	actions := make([]string, 35)
	for i := range actions {
		actions[i] = "AXPress"
	}
	actions[0] = strings.Repeat("x", 129)
	f := &gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "ref", "nativeRole": "AXButton", "enabled": true, "actions": actions, "valueSettable": false}}}
	g := newGatewayFixture(t, f, false)
	obs, err := g.Observe(ctx, p, model.Surface{Kind: "native", BundleID: "fixture.app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Nodes) != 1 || len(obs.Nodes[0].Actions) != 31 {
		t.Fatal("advertised actions not bounded or oversized name retained")
	}
	found := false
	for _, why := range obs.Nodes[0].Unavailable {
		found = found || why == "truncated:actions"
	}
	if !found {
		t.Fatal("incomplete advertised action coverage not reported")
	}
}
