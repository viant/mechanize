package model

import "testing"

func TestBrowserActivateTabExactMetadataAction(t *testing.T) {
	valid := Step{ID: "activate", Action: "browser.activateTab", Target: Selector{Surface: Surface{Kind: "web", Origin: "https://fixture.test", TabID: "profile/browser/42"}, Cardinality: "one"}, TimeoutMs: 3000, Effect: Effect{Class: ExternalNonIdempotent, BusinessKey: map[string]Value{"request": {Kind: StringValue, String: "request"}}}}
	if e := valid.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Step){func(s *Step) { s.Target.Surface.TabID = "" }, func(s *Step) { s.Target.Surface.TabID = "https://fixture.test/path" }, func(s *Step) { s.Target.Surface.Origin += "/path" }, func(s *Step) { s.Target.Surface.Title = "login" }, func(s *Step) { s.Bind = "private" }, func(s *Step) { s.Precondition = &Predicate{} }, func(s *Step) { s.Postcondition = &Predicate{} }, func(s *Step) { s.ResultType = StringValue }, func(s *Step) { s.Effect.Class = ReadOnly }, func(s *Step) { s.Effect.BusinessKey = nil }, func(s *Step) { s.Arguments = map[string]Value{"value": {Kind: StringValue, String: "input"}} }} {
		s := valid
		mutate(&s)
		if s.Validate() == nil {
			t.Fatalf("unsafe activation accepted: %+v", s)
		}
	}
	if a, ok := ActionByMethod("activateTab"); !ok || a.Action != "browser.activate" {
		t.Fatal("existing renderer action changed")
	}
	if TabActivationReason("PRIVATE_CANARY") != "tabActivationUnavailable" {
		t.Fatal("arbitrary reason exposed")
	}
}
