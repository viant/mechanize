package model

import "testing"

func TestNativeRootScopeIsClosedAndRequiresNamedTargets(t *testing.T) {
	for _, root := range []string{"menuBar", "focusedElement"} {
		selector := Selector{Surface: Surface{Kind: "native", BundleID: "com.apple.finder"}, Scope: Scope{NativeRoot: root}, Cardinality: "one", Locator: &Locator{Strategy: "role", Value: Value{Kind: StringValue, String: "textbox"}, Exact: true}}
		if err := selector.Validate(); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"unknown", "web", "window", "frame", "ancestor"} {
			t.Run(root+"_"+bad, func(t *testing.T) {
				s := selector
				switch bad {
				case "unknown":
					s.Scope.NativeRoot = "desktop"
				case "web":
					s.Surface = Surface{Kind: "web", Origin: "https://fixture.test"}
				case "window":
					s.Scope.Window = map[string]Value{"title": {Kind: StringValue, String: "Finder"}}
				case "frame":
					s.Scope.Frame = map[string]Value{"id": {Kind: StringValue, String: "root"}}
				case "ancestor":
					a := selector
					a.Scope.NativeRoot = ""
					s.Ancestor = &a
				}
				if s.Validate() == nil {
					t.Fatal("mixed native root accepted")
				}
			})
		}
		step := Step{ID: "read", Action: "element.read", Target: selector, Arguments: map[string]Value{"attribute": {Kind: StringValue, String: "name"}}, TimeoutMs: 1000, Effect: Effect{Class: ReadOnly}}
		if err := step.Validate(); err != nil {
			t.Fatal(err)
		}
		step.Target.Locator = nil
		step.Action = "expect"
		step.Arguments = nil
		step.Assertion = &Assertion{Matcher: "toBeEnabled"}
		if step.Validate() == nil {
			t.Fatal("blind native root assertion accepted")
		}
		step.Action = "app.activate"
		step.Assertion = nil
		step.Effect = Effect{Class: ExternalNonIdempotent, BusinessKey: map[string]Value{"bundle": {Kind: StringValue, String: "finder"}}}
		if step.Validate() == nil {
			t.Fatal("native root activation accepted")
		}
	}
}
