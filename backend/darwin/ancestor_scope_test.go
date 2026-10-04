package darwin

import (
	"testing"

	"github.com/viant/mechanize/model"
)

func calculatorAncestorTree() []model.Node {
	return []model.Node{
		scopedWindowNode("app", "", "AXApplication", "Calculator", ""),
		scopedWindowNode("window", "app", "AXWindow", "Calculator", ""),
		scopedWindowNode("resultview", "window", "AXScrollArea", "", "StandardResultView"),
		scopedWindowNode("result", "resultview", "AXStaticText", "", ""),
		scopedWindowNode("inputview", "window", "AXScrollArea", "", "StandardInputView"),
		scopedWindowNode("input", "inputview", "AXStaticText", "", ""),
	}
}
func calculatorAncestorTarget() model.Selector {
	target := scopedWindowSelector()
	target.Scope.Window["title"] = model.Value{Kind: model.StringValue, String: "Calculator"}
	target.Locator.Strategy = "role"
	target.Locator.Value.String = "text"
	ancestor := target
	ancestor.Scope.Window = nil
	ancestor.Locator = &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "StandardResultView"}, Exact: true}
	target.Ancestor = &ancestor
	return target
}
func TestAncestorScopeSelectsAnonymousResultAndFailsAmbiguity(t *testing.T) {
	target := calculatorAncestorTarget()
	nodes := calculatorAncestorTree()
	nodes[5].Unavailable = []string{"name"}
	if node, err := resolve(model.Observation{Nodes: nodes}, target, nil); err != nil || node.Ref.ID != "result" {
		t.Fatalf("result scope: %+v %v", node, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]model.Node) []model.Node
	}{
		{"ambiguousAncestor", func(nodes []model.Node) []model.Node { nodes[4].Identifier = "StandardResultView"; return nodes }},
		{"ambiguousText", func(nodes []model.Node) []model.Node {
			return append(nodes, scopedWindowNode("result2", "resultview", "AXStaticText", "", ""))
		}},
		{"unknownAncestorID", func(nodes []model.Node) []model.Node { nodes[4].Unavailable = []string{"identifier"}; return nodes }},
		{"unknownDescendantRole", func(nodes []model.Node) []model.Node {
			nodes[3].Unavailable = []string{"role"}
			nodes[3].NativeRole = ""
			nodes[3].Role = ""
			return nodes
		}},
		{"orphan", func(nodes []model.Node) []model.Node { nodes[5].ParentID = "missing"; return nodes }},
		{"cycle", func(nodes []model.Node) []model.Node { nodes[2].ParentID = "result"; return nodes }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolve(model.Observation{Nodes: tc.mutate(calculatorAncestorTree())}, target, nil); err == nil {
				t.Fatal("unsafe ancestor evidence accepted")
			}
		})
	}
	// An ancestor is never its own descendant.
	target.Locator = target.Ancestor.Locator
	if _, err := resolve(model.Observation{Nodes: calculatorAncestorTree()}, target, nil); err == nil {
		t.Fatal("ancestor selected as descendant")
	}
}

func TestNestedAncestorScopeRejectsCrossWindowAndDepth(t *testing.T) {
	nodes := calculatorAncestorTree()
	outer := calculatorAncestorTarget()
	window := outer
	window.Locator = &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "outer"}, Exact: true}
	window.Ancestor = nil
	nodes = append(nodes, scopedWindowNode("outer", "window", "AXGroup", "", "outer"))
	nodes[2].ParentID = "outer"
	outer.Ancestor.Ancestor = &window
	if node, err := resolve(model.Observation{Nodes: nodes}, outer, nil); err != nil || node.Ref.ID != "result" {
		t.Fatalf("nested scope: %+v %v", node, err)
	}
	bad := calculatorAncestorTarget()
	bad.Ancestor.Scope.Window = map[string]model.Value{"title": {Kind: model.StringValue, String: "Other"}}
	if _, err := resolve(model.Observation{Nodes: nodes}, bad, nil); err == nil {
		t.Fatal("cross-window ancestor accepted")
	}
	bad = calculatorAncestorTarget()
	bad.Ancestor.Surface.BundleID = "other.app"
	if _, err := resolve(model.Observation{Nodes: nodes}, bad, nil); err == nil {
		t.Fatal("cross-surface ancestor accepted")
	}
	bad = calculatorAncestorTarget()
	bad.Ancestor = &bad
	if _, err := resolve(model.Observation{Nodes: nodes}, bad, nil); err == nil {
		t.Fatal("cyclic selector accepted")
	}
}

func TestAncestorStaticTextReadResolvesFreshSnapshot(t *testing.T) {
	ctx, principal := nativeActor(t)
	fixture := &staticTextFixture{gatewayFixture: gatewayFixture{complete: true}, text: "391"}
	for _, node := range calculatorAncestorTree() {
		fixture.nodes = append(fixture.nodes, map[string]any{"ref": node.Ref.ID, "parentRef": node.ParentID, "nativeRole": node.NativeRole, "identifier": node.Identifier, "name": node.Name})
	}
	gateway, err := NewGateway(fixture, GatewayOptions{AllowedBundles: []string{"fixture.app"}, AllowedStaticTextBundles: []string{"fixture.app"}})
	if err != nil {
		t.Fatal(err)
	}
	step := nativeStep("element.read")
	step.Effect.Class = model.ReadOnly
	step.Target = calculatorAncestorTarget()
	step.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: "staticText"}}
	for _, text := range []string{"391", "392"} {
		fixture.text = text
		result, err := gateway.Execute(ctx, principal, step, nil)
		if err != nil || result.Value == nil || result.Value.String != text || fixture.readParams["elementRef"] != "result" {
			t.Fatalf("fresh result read: %+v %v params=%+v", result, err, fixture.readParams)
		}
	}
	snapshots := 0
	for _, call := range fixture.calls {
		if call == "elements.snapshot" {
			snapshots++
		}
	}
	if snapshots != 2 {
		t.Fatalf("reads did not resolve fresh snapshots: %d", snapshots)
	}
}
