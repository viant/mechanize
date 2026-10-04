package model

import "testing"

func TestStructuredAppOpenCannotManufactureInputScopeOrReadEffect(t *testing.T) {
	base := Step{ID: "launch", Action: "app.open", TimeoutMs: 1000, Effect: Effect{Class: ExternalNonIdempotent}, Target: Selector{Surface: Surface{Kind: "native", BundleID: "com.apple.mail"}, Cardinality: "one"}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	changes := []func(*Step){
		func(s *Step) { s.Effect.Class = ReadOnly },
		func(s *Step) { s.Target.Surface = Surface{Kind: "web", Origin: "https://example.test"} },
		func(s *Step) { s.Target.Surface.BundleID = "/Applications/Mail.app" },
		func(s *Step) { s.Target.Surface.BundleID = "com.apple.mail\nother" },
		func(s *Step) { s.Target.Scope.Window = map[string]Value{"title": {Kind: StringValue, String: "Inbox"}} },
		func(s *Step) {
			s.Target.Locator = &Locator{Strategy: "id", Value: Value{Kind: StringValue, String: "save"}, Exact: true}
		},
		func(s *Step) { s.Arguments = map[string]Value{"path": {Kind: StringValue, String: "/tmp/app"}} },
		func(s *Step) { s.Bind = "businessSuccess" },
	}
	for i, change := range changes {
		step := base
		change(&step)
		if err := step.Validate(); err == nil {
			t.Fatalf("unsafe change%d accepted", i)
		}
	}
}
