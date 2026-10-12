package model

import (
	"strings"
	"testing"
)

func windowTextFixture() Value {
	return Value{Kind: ObjectValue, Object: map[string]Value{"windowId": {Kind: NumberValue, Number: 1}, "text": {Kind: StringValue, String: "=SUM(17,23)"}, "focusRole": {Kind: StringValue, String: "AXTextArea"}, "focusIdentifier": {Kind: StringValue, String: "editor"}, "focusName": {Kind: StringValue}}}
}
func TestWindowTextClosedBoundedData(t *testing.T) {
	v := windowTextFixture()
	if _, err := WindowText(v); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Value){func(v *Value) { v.Object["extra"] = Value{Kind: StringValue} }, func(v *Value) { v.Object["text"] = Value{Kind: StringValue, String: "line\ncommand"} }, func(v *Value) { v.Object["text"] = Value{Kind: StringValue, String: strings.Repeat("x", 4097)} }, func(v *Value) { v.Object["windowId"] = Value{Kind: NumberValue, Number: 0} }, func(v *Value) { v.Object["focusIdentifier"] = Value{Kind: StringValue} }, func(v *Value) { v.Object["focusRole"] = Value{Kind: StringValue, String: "AXButton"} }, func(v *Value) { v.Object["focusIdentifier"] = Value{Kind: StringValue, String: "password"} }} {
		v = windowTextFixture()
		change(&v)
		if err := ValidateWindowText(v); err == nil {
			t.Fatal("invalid text request accepted")
		}
	}
	v = windowTextFixture()
	v.Object["text"] = Value{Kind: ReferenceValue, Ref: "input.text", Expected: StringValue}
	if err := ValidateWindowText(v); err != nil {
		t.Fatal(err)
	}
	if _, err := WindowText(v); err == nil {
		t.Fatal("unresolved text accepted")
	}
	step := Step{Action: "window.typeText", Arguments: map[string]Value{"windowText": v}}
	if _, err := step.ResolveArguments(map[string]Value{"input.text": {Kind: StringValue, String: "bad\x00text"}}); err == nil {
		t.Fatal("resolved control character accepted")
	}
}
