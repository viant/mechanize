package model

import (
	"strconv"
	"testing"
)

func windowKeyStep() Step {
	return Step{ID: "escape", Action: "window.pressSessionKey", TimeoutMs: 1000, Effect: Effect{Class: ExternalNonIdempotent}, Target: Selector{Surface: Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 1, ProcessStartToken: "100:1"}, Cardinality: "one"}, Arguments: map[string]Value{"windowKey": {Kind: ObjectValue, Object: map[string]Value{"windowId": {Kind: NumberValue, Number: 9625}, "key": {Kind: StringValue, String: "Escape"}}}}}
}
func TestWindowSessionKeyClosedNativeContract(t *testing.T) {
	for _, mode := range []string{"valid", "maxID", "zero", "overflow", "stringID", "missingKey", "extra", "invalidKey", "duplicateModifier", "web", "noPID", "noBirth", "locator", "root", "frame", "window", "ancestor"} {
		t.Run(mode, func(t *testing.T) {
			s := windowKeyStep()
			v := s.Arguments["windowKey"]
			switch mode {
			case "maxID":
				v.Object["windowId"] = Value{Kind: NumberValue, Number: 4294967295}
			case "zero":
				v.Object["windowId"] = Value{Kind: NumberValue}
			case "overflow":
				v.Object["windowId"] = Value{Kind: NumberValue, Number: 4294967296}
			case "stringID":
				v.Object["windowId"] = Value{Kind: StringValue, String: "9625"}
			case "missingKey":
				delete(v.Object, "key")
			case "extra":
				v.Object["pointer"] = Value{Kind: BoolValue}
			case "invalidKey":
				v.Object["key"] = Value{Kind: StringValue, String: "text paragraph"}
			case "duplicateModifier":
				v.Object["key"] = Value{Kind: StringValue, String: "Cmd+Command+S"}
			case "web":
				s.Target.Surface = Surface{Kind: "web", Origin: "https://example.com"}
			case "noPID":
				s.Target.Surface.ProcessID = 0
				s.Target.Surface.ProcessStartToken = ""
			case "noBirth":
				s.Target.Surface.ProcessStartToken = ""
			case "locator":
				s.Target.Locator = &Locator{Strategy: "id", Value: Value{Kind: StringValue, String: "field"}, Exact: true}
			case "root":
				s.Target.Scope.NativeRoot = "focusedElement"
			case "frame":
				s.Target.Scope.Frame = map[string]Value{"id": {Kind: StringValue, String: "x"}}
			case "window":
				s.Target.Scope.Window = map[string]Value{"title": {Kind: StringValue, String: "x"}}
			case "ancestor":
				a := s.Target
				s.Target.Ancestor = &a
			}
			s.Arguments["windowKey"] = v
			e := s.Validate()
			if (e == nil) != (mode == "valid" || mode == "maxID") {
				t.Fatal(mode, e)
			}
		})
	}
}
func TestWindowSessionKeyTypedReferencesResolveBounds(t *testing.T) {
	s := windowKeyStep()
	s.Arguments["windowKey"] = Value{Kind: ObjectValue, Object: map[string]Value{"windowId": {Kind: ReferenceValue, Expected: NumberValue, Ref: "input.window"}, "key": {Kind: ReferenceValue, Expected: StringValue, Ref: "input.key"}}}
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ResolveArguments(map[string]Value{"input.window": {Kind: NumberValue, Number: 9625}, "input.key": {Kind: StringValue, String: "Escape"}}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ResolveArguments(map[string]Value{"input.window": {Kind: NumberValue, Number: -1}, "input.key": {Kind: StringValue, String: "Escape"}}); e == nil {
		t.Fatal("invalid runtime window accepted")
	}
}

func TestKeyboardChordFunctionKeysAreClosedAndKeepModifiers(t *testing.T) {
	for i := 1; i <= 20; i++ {
		key := "F" + strconv.Itoa(i)
		if err := ValidateKeyboardChord(key); err != nil {
			t.Errorf("%s rejected: %v", key, err)
		}
		if err := ValidateKeyboardChord("Cmd+Shift+" + key); err != nil {
			t.Errorf("modified %s rejected: %v", key, err)
		}
	}
	for _, key := range []string{"F0", "F01", "F21", "F0001", "0x7A", "123"} {
		if err := ValidateKeyboardChord(key); err == nil {
			t.Errorf("invalid function/raw key %q accepted", key)
		}
	}
}
