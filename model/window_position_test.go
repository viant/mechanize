package model

import "testing"

func windowPositionStep() Step {
	return Step{ID: "move", Action: "window.moveTo", TimeoutMs: 1000, Effect: Effect{Class: ExternalNonIdempotent}, Target: Selector{Surface: Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 1, ProcessStartToken: "1:2"}, Cardinality: "one", Locator: &Locator{Strategy: "role", Value: Value{Kind: StringValue, String: "window"}, Exact: true}}, Arguments: map[string]Value{"position": {Kind: ObjectValue, Object: map[string]Value{"x": {Kind: NumberValue, Number: 100}, "y": {Kind: NumberValue, Number: 100}}}}}
}
func TestWindowPositionClosedArgumentsAndNativeTarget(t *testing.T) {
	for _, mode := range []string{"valid", "negative", "low", "high", "missing", "extra", "string", "duration", "web", "noPID", "noBirth", "all", "root", "ancestor", "windowScope", "readEffect"} {
		t.Run(mode, func(t *testing.T) {
			s := windowPositionStep()
			position := s.Arguments["position"]
			switch mode {
			case "negative":
				position.Object["x"] = Value{Kind: NumberValue, Number: -32768}
			case "low":
				position.Object["x"] = Value{Kind: NumberValue, Number: -32769}
			case "high":
				position.Object["y"] = Value{Kind: NumberValue, Number: 32768}
			case "missing":
				delete(position.Object, "y")
			case "extra":
				position.Object["z"] = Value{Kind: NumberValue}
			case "string":
				position.Object["x"] = Value{Kind: StringValue, String: "100"}
			case "duration":
				position.Object["x"] = Value{Kind: DurationValue, Number: 100}
			case "web":
				s.Target.Surface = Surface{Kind: "web", Origin: "https://example.com"}
			case "noPID":
				s.Target.Surface.ProcessID = 0
				s.Target.Surface.ProcessStartToken = ""
			case "noBirth":
				s.Target.Surface.ProcessStartToken = ""
			case "all":
				s.Target.Cardinality = "all"
			case "root":
				s.Target.Scope.NativeRoot = "focusedElement"
			case "ancestor":
				a := s.Target
				s.Target.Ancestor = &a
			case "windowScope":
				s.Target.Scope.Window = map[string]Value{"title": {Kind: StringValue, String: "Window"}}
			case "readEffect":
				s.Effect.Class = ReadOnly
			}
			s.Arguments["position"] = position
			e := s.Validate()
			if (e == nil) != (mode == "valid" || mode == "negative") {
				t.Fatalf("validation %v", e)
			}
		})
	}
}
func TestWindowPositionRuntimeReferenceCannotEscapeBounds(t *testing.T) {
	s := windowPositionStep()
	position := s.Arguments["position"]
	s.Arguments["position"] = Value{Kind: ReferenceValue, Expected: ObjectValue, Ref: "input.position"}
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ResolveArguments(map[string]Value{"input.position": position}); e != nil {
		t.Fatal(e)
	}
	position.Object["x"] = Value{Kind: NumberValue, Number: 32768}
	if _, e := s.ResolveArguments(map[string]Value{"input.position": position}); e == nil {
		t.Fatal("unbounded runtime position accepted")
	}
}
