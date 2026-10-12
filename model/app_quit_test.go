package model

import "testing"

func TestAppQuitRequiresExactApplicationAndBusinessKey(t *testing.T) {
	base := Step{ID: "quit", Action: "app.quit", TimeoutMs: 1000, Effect: Effect{Class: ExternalNonIdempotent, BusinessKey: map[string]Value{"bundleID": {Kind: StringValue, String: "com.apple.mail"}}}, Target: Selector{Surface: Surface{Kind: "native", BundleID: "com.apple.mail"}, Cardinality: "one"}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Step){func(s *Step) { s.Effect.BusinessKey = nil }, func(s *Step) { s.Effect.Class = ReadOnly }, func(s *Step) { s.Target.Surface.BundleID = "/Applications/Mail.app" }, func(s *Step) {
		s.Target.Locator = &Locator{Strategy: "id", Value: Value{Kind: StringValue, String: "x"}, Exact: true}
	}, func(s *Step) { s.Bind = "active" }} {
		step := base
		change(&step)
		if err := step.Validate(); err == nil {
			t.Fatalf("unsafe quit accepted %+v", step)
		}
	}
}
