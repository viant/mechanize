package darwin

import (
	"strings"
	"testing"

	"github.com/viant/mechanize/model"
)

func scopedWindowNode(id, parent, nativeRole, name, identifier string) model.Node {
	return model.Node{Ref: model.ElementRef{ID: id}, ParentID: parent, Role: role(nativeRole), NativeRole: nativeRole, Name: name, Identifier: identifier}
}
func scopedWindowSelector() model.Selector {
	target := nativeStep("element.press").Target
	target.Locator.Value.String = "app.badge"
	target.Scope.Window = map[string]model.Value{"title": {Kind: model.StringValue, String: "Mechanize"}}
	return target
}
func scopedWindowTree() []model.Node {
	menu := scopedWindowNode("menu", "app", "AXMenuBarItem", "", "")
	menu.Unavailable = []string{"identifier", "name"}
	other := scopedWindowNode("otherbadge", "otherwindow", "AXButton", "", "")
	other.Unavailable = []string{"identifier"}
	return []model.Node{
		scopedWindowNode("app", "", "AXApplication", "Mechanize", ""),
		menu,
		scopedWindowNode("window", "app", "AXWindow", "Mechanize", ""),
		scopedWindowNode("group", "window", "AXGroup", "", ""),
		scopedWindowNode("badge", "group", "AXButton", "Ready", "app.badge"),
		scopedWindowNode("otherwindow", "app", "AXWindow", "Settings", ""), other,
	}
}

func TestWindowScopeIgnoresMetadataOutsideUniqueSubtree(t *testing.T) {
	observation := model.Observation{Nodes: scopedWindowTree()}
	for _, wantedRole := range []string{"", "window", "AXWindow"} {
		target := scopedWindowSelector()
		if wantedRole != "" {
			target.Scope.Window["role"] = model.Value{Kind: model.StringValue, String: wantedRole}
		}
		node, err := resolve(observation, target, nil)
		if err != nil || node.Ref.ID != "badge" {
			t.Fatalf("node=%+v err=%v", node, err)
		}
	}
	// Removing the explicit boundary restores the global uniqueness gate.
	target := scopedWindowSelector()
	target.Scope.Window = nil
	if _, err := resolve(observation, target, nil); err == nil {
		t.Fatal("unscoped unavailable identifier accepted")
	}
}

func TestWindowScopeRejectsIncompleteAndAmbiguousEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]model.Node) []model.Node
	}{
		{"duplicateTitles", func(nodes []model.Node) []model.Node { nodes[5].Name = "Mechanize"; return nodes }},
		{"unknownWindowTitle", func(nodes []model.Node) []model.Node { nodes[5].Unavailable = []string{"name"}; return nodes }},
		{"unknownRole", func(nodes []model.Node) []model.Node { nodes[1].Unavailable = []string{"role"}; return nodes }},
		{"candidateIdentifier", func(nodes []model.Node) []model.Node { nodes[4].Unavailable = []string{"identifier"}; return nodes }},
		{"duplicateRefs", func(nodes []model.Node) []model.Node { nodes[1].Ref.ID = "badge"; return nodes }},
		{"missingRef", func(nodes []model.Node) []model.Node { nodes[1].Ref.ID = ""; return nodes }},
		{"orphan", func(nodes []model.Node) []model.Node { nodes[1].ParentID = "missing"; return nodes }},
		{"cycle", func(nodes []model.Node) []model.Node { nodes[0].ParentID = "badge"; return nodes }},
		{"missingWindow", func(nodes []model.Node) []model.Node { nodes[2].Name = "Other"; return nodes }},
		{"duplicateCandidate", func(nodes []model.Node) []model.Node {
			return append(nodes, scopedWindowNode("badge2", "window", "AXButton", "Ready", "app.badge"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if node, err := resolve(model.Observation{Nodes: test.mutate(scopedWindowTree())}, scopedWindowSelector(), nil); err == nil {
				t.Fatalf("unsafe resolution: %+v", node)
			}
		})
	}
	if _, err := resolve(model.Observation{Nodes: scopedWindowTree(), Truncated: true}, scopedWindowSelector(), nil); err == nil {
		t.Fatal("truncated window tree accepted")
	}
	nodes := scopedWindowTree()
	parent := "otherwindow"
	for i := 0; i < 21; i++ {
		id := strings.Repeat("x", i+1)
		nodes = append(nodes, scopedWindowNode(id, parent, "AXGroup", "", ""))
		parent = id
	}
	if _, err := resolve(model.Observation{Nodes: nodes}, scopedWindowSelector(), nil); err == nil {
		t.Fatal("excessive parent depth accepted")
	}
}

func TestWindowScopeRejectsUnsupportedAndResolvesParameters(t *testing.T) {
	for _, scope := range []map[string]model.Value{
		{"documentKey": {Kind: model.StringValue, String: "document"}},
		{"role": {Kind: model.StringValue, String: "window"}},
		{"title": {Kind: model.StringValue, String: "Mechanize"}, "documentKey": {Kind: model.StringValue, String: "document"}},
		{"title": {Kind: model.StringValue, String: "Mechanize"}, "role": {Kind: model.StringValue, String: "dialog"}},
	} {
		target := scopedWindowSelector()
		target.Scope.Window = scope
		if _, err := resolve(model.Observation{Nodes: scopedWindowTree()}, target, nil); err == nil {
			t.Fatalf("unsupported scope admitted: %+v", scope)
		}
	}
	target := scopedWindowSelector()
	target.Scope.Window["title"] = model.Value{Kind: model.ReferenceValue, Ref: "input.window", Expected: model.StringValue}
	if node, err := resolve(model.Observation{Nodes: scopedWindowTree()}, target, map[string]model.Value{"input.window": {Kind: model.StringValue, String: "Mechanize"}}); err != nil || node.Ref.ID != "badge" {
		t.Fatalf("parameter resolution: %+v %v", node, err)
	}
}

func TestWindowScopedActionResolvesFreshSnapshots(t *testing.T) {
	ctx, principal := nativeActor(t)
	fixture := &gatewayFixture{complete: true, mutation: true}
	for _, node := range scopedWindowTree() {
		fixture.nodes = append(fixture.nodes, map[string]any{"ref": node.Ref.ID, "parentRef": node.ParentID, "nativeRole": node.NativeRole, "name": node.Name, "identifier": node.Identifier, "unavailable": node.Unavailable, "enabled": true})
	}
	gateway := newGatewayFixture(t, fixture, true)
	step := nativeStep("element.press")
	step.Target = scopedWindowSelector()
	for i := 0; i < 2; i++ {
		result, err := gateway.Execute(ctx, principal, step, nil)
		if err != nil || result.DispatchState != "dispatched" {
			t.Fatalf("scoped action: %+v %v", result, err)
		}
	}
	snapshots, actions := 0, 0
	for _, call := range fixture.calls {
		if call == "elements.snapshot" {
			snapshots++
		}
		if call == "elements.press" {
			actions++
		}
	}
	if snapshots != 2 || actions != 2 {
		t.Fatalf("snapshots=%d actions=%d", snapshots, actions)
	}
}

func TestWindowScopedActionStopsBeforeAuthorityOnUnknownCandidate(t *testing.T) {
	ctx, principal := nativeActor(t)
	fixture := &gatewayFixture{complete: true, mutation: true, nodes: []map[string]any{
		{"ref": "app", "nativeRole": "AXApplication"},
		{"ref": "window", "parentRef": "app", "nativeRole": "AXWindow", "name": "Mechanize"},
		{"ref": "candidate", "parentRef": "window", "nativeRole": "AXButton", "unavailable": []string{"identifier"}},
	}}
	gateway := newGatewayFixture(t, fixture, true)
	step := nativeStep("element.press")
	step.Target = scopedWindowSelector()
	if _, err := gateway.Execute(ctx, principal, step, nil); err == nil {
		t.Fatal("unknown candidate accepted")
	}
	for _, call := range fixture.calls {
		if call == "lease.install" || call == "elements.press" {
			t.Fatalf("authority used after failed scope proof: %s", call)
		}
	}
}

// Exact window predicates must be able to resolve the selected AXWindow itself;
// selecting its descendants alone hides the independently observed boundary.
func TestWindowScopeIncludesExactSelectedRootWithoutOtherWindows(t *testing.T) {
	name := model.Value{Kind: model.StringValue, String: "Mechanize"}
	for _, helperScoped := range []bool{false, true} {
		t.Run(map[bool]string{false: "completeApplicationTree", true: "helperScopedTree"}[helperScoped], func(t *testing.T) {
			nodes := scopedWindowTree()
			observation := model.Observation{Nodes: nodes}
			if helperScoped {
				root := nodes[2]
				root.ParentID = ""
				observation.Nodes = []model.Node{root, nodes[3], nodes[4]}
				observation.WindowScope = map[string]string{"title": "Mechanize"}
			}
			target := scopedWindowSelector()
			target.Locator = &model.Locator{Strategy: "role", Value: model.Value{Kind: model.StringValue, String: "window"}, Name: &name, Exact: true}
			node, err := resolve(observation, target, nil)
			if err != nil || node.Ref.ID != "window" {
				t.Fatal("exact selected window root was hidden", err)
			}
			// Generic role selection still excludes the other application window.
			target.Locator.Name = nil
			if node, err = resolve(observation, target, nil); err != nil || node.Ref.ID != "window" {
				t.Fatal("window scope broadened to another root", err)
			}
			// Descendant element routing remains within the same exact boundary.
			if node, err = resolve(observation, scopedWindowSelector(), nil); err != nil || node.Ref.ID != "badge" {
				t.Fatal("root inclusion changed descendant target", err)
			}
			observation.Truncated = true
			if _, err = resolve(observation, target, nil); err == nil {
				t.Fatal("root inclusion accepted incomplete scope")
			}
		})
	}
}
