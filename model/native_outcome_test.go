package model

import "testing"

func TestNativeOutcomeWindowMismatchRejectedBeforeAdmission(t *testing.T) {
	s := func(v string) Value { return Value{Kind: StringValue, String: v} }
	for _, outcome := range []string{"postcondition", "reconcile"} {
		t.Run(outcome, func(t *testing.T) {
			predicate := &Predicate{Adapter: "native", Name: "valueEquals", Inputs: map[string]Value{"windowTitle": s("Setup"), "windowRole": s("AXWindow")}}
			step := Step{Target: Selector{Surface: Surface{Kind: "native"}, Scope: Scope{Window: map[string]Value{"title": s("Setup")}}}, Effect: Effect{Class: ExternalNonIdempotent}}
			if outcome == "postcondition" {
				step.Postcondition = predicate
			} else {
				step.Effect.Reconcile = predicate
			}
			if ValidateNativeScopedOutcome(step, nil) == nil {
				t.Fatal("extra window role admitted")
			}
			step.Target.Scope.Window["role"] = s("AXWindow")
			if err := ValidateNativeScopedOutcome(step, nil); err != nil {
				t.Fatal(err)
			}
			predicate.Inputs["windowTitle"] = s("Other")
			if ValidateNativeScopedOutcome(step, nil) == nil {
				t.Fatal("substituted window admitted")
			}
			predicate.Inputs["windowTitle"] = Value{Kind: ReferenceValue, Ref: "input.title"}
			if err := ValidateNativeScopedOutcome(step, nil); err != nil {
				t.Fatal("static reference must defer", err)
			}
			if ValidateNativeScopedOutcome(step, map[string]Value{}) == nil {
				t.Fatal("unresolved reference admitted")
			}
			if err := ValidateNativeScopedOutcome(step, map[string]Value{"input.title": s("Setup")}); err != nil {
				t.Fatal(err)
			}
			if ValidateNativeScopedOutcome(step, map[string]Value{"input.title": s("Other")}) == nil {
				t.Fatal("resolved substitution admitted")
			}
		})
	}
}

func TestExplicitNativeOutcomeRootCannotBroadenOrChange(t *testing.T) {
	step := Step{Target: Selector{Surface: Surface{Kind: "native"}, Scope: Scope{NativeRoot: "menuBar"}}, Effect: Effect{Class: ExternalNonIdempotent}, Postcondition: &Predicate{Adapter: "native", Name: "literalValueMatches", Inputs: map[string]Value{}}}
	if ValidateNativeScopedOutcome(step, nil) == nil {
		t.Fatal("unscoped window outcome admitted after menu action")
	}
	step.Postcondition.Inputs["nativeRoot"] = Value{Kind: StringValue, String: "focusedElement"}
	if ValidateNativeScopedOutcome(step, nil) == nil {
		t.Fatal("substituted focus outcome admitted")
	}
	step.Postcondition.Inputs["nativeRoot"] = Value{Kind: StringValue, String: "menuBar"}
	if err := ValidateNativeScopedOutcome(step, nil); err != nil {
		t.Fatal(err)
	}
	step.Postcondition.Inputs["nativeRoot"] = Value{Kind: ReferenceValue, Ref: "input.root"}
	if err := ValidateNativeScopedOutcome(step, nil); err != nil {
		t.Fatal("static reference should defer", err)
	}
	if ValidateNativeScopedOutcome(step, map[string]Value{"input.root": {Kind: StringValue, String: "focusedElement"}}) == nil {
		t.Fatal("dynamic root substitution admitted")
	}
	if err := ValidateNativeScopedOutcome(step, map[string]Value{"input.root": {Kind: StringValue, String: "menuBar"}}); err != nil {
		t.Fatal(err)
	}
	if ValidateNativeScopedOutcome(step, map[string]Value{}) == nil {
		t.Fatal("unresolved root admitted")
	}
}
