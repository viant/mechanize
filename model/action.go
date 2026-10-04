package model

import (
	"strings"
	"unicode/utf8"
)

// ActionDefinition is the single closed registry used by validation and discovery.
type ActionDefinition struct {
	Action       string
	Method       string
	Argument     string
	ArgumentType ValueKind
	Capability   string
	ReadOnly     bool
}

func Actions() []ActionDefinition {
	return []ActionDefinition{
		{Action: "app.activate", Method: "activate", Capability: "appActivation"},
		{Action: "app.open", Method: "open", Capability: "appLaunch"},
		{Action: "window.pressSessionKey", Method: "pressWindowKey", Argument: "windowKey", ArgumentType: ObjectValue, Capability: "windowSessionKeyboard"},
		{Action: "window.clickFrame", Method: "clickWindowFrame", Argument: "frameClick", ArgumentType: ObjectValue, Capability: "windowFrameClick"},
		{Action: "window.moveTo", Method: "moveTo", Argument: "position", ArgumentType: ObjectValue, Capability: "windowPosition"},
		{Action: "element.focus", Method: "focus", Capability: "targetedFocus"},
		{Action: "element.press", Method: "click", Capability: "semanticPress"},
		{Action: "element.submit", Method: "submit", Capability: "semanticSubmit"},
		{Action: "element.replaceText", Method: "replaceText", Argument: "value", ArgumentType: StringValue, Capability: "replaceText"},
		{Action: "element.fill", Method: "fill", Argument: "value", ArgumentType: StringValue, Capability: "replaceValue"},
		{Action: "element.check", Method: "check", Capability: "ensureChecked"},
		{Action: "element.uncheck", Method: "uncheck", Capability: "ensureChecked"},
		{Action: "element.select", Method: "select", Argument: "value", ArgumentType: StringValue, Capability: "selectOption"},
		{Action: "element.pressKey", Method: "pressKey", Argument: "key", ArgumentType: StringValue, Capability: "targetedKeyboard"},
		{Action: "element.pressSessionKey", Method: "pressSessionKey", Argument: "key", ArgumentType: StringValue, Capability: "sessionKeyboard"},
		{Action: "element.read", Method: "read", Argument: "attribute", ArgumentType: StringValue, Capability: "attributeRead", ReadOnly: true},
		{Action: "expect", Method: "expect", Capability: "boundedObservation", ReadOnly: true},
	}
}
func ActionByName(name string) (ActionDefinition, bool) {
	for _, a := range Actions() {
		if a.Action == name {
			return a, true
		}
	}
	return ActionDefinition{}, false
}
func ActionByMethod(name string) (ActionDefinition, bool) {
	for _, a := range Actions() {
		if a.Method == name {
			return a, true
		}
	}
	return ActionDefinition{}, false
}

// ResolveArguments validates resolved runtime values against the action contract.
func (s Step) ResolveArguments(bindings map[string]Value) (map[string]Value, error) {
	out := make(map[string]Value, len(s.Arguments))
	a, ok := ActionByName(s.Action)
	if !ok {
		return nil, argumentError("unknown action")
	}
	for k, v := range s.Arguments {
		x, err := ResolveValue(v, bindings)
		if err != nil {
			return nil, err
		}
		if k != a.Argument || x.Kind != a.ArgumentType {
			return nil, argumentError("resolved argument does not match action contract")
		}
		out[k] = x
	}
	if a.Argument != "" && len(out) != 1 {
		return nil, argumentError("missing action argument")
	}
	if s.Action == "window.moveTo" {
		if _, _, err := WindowPosition(out["position"]); err != nil {
			return nil, err
		}
	}
	if s.Action == "window.pressSessionKey" {
		if _, _, err := WindowSessionKey(out["windowKey"]); err != nil {
			return nil, err
		}
	}
	if s.Action == "window.clickFrame" {
		if _, _, _, err := WindowFrameClick(out["frameClick"]); err != nil {
			return nil, err
		}
	}
	if s.Action == "element.replaceText" {
		if err := ValidateLiteralText(out["value"].String); err != nil {
			return nil, err
		}
	}
	return out, nil
}

type argumentError string

func (e argumentError) Error() string { return string(e) }

// WindowPosition validates the closed logical-point position object. Negative
// coordinates support displays left/above the primary display; no clamping occurs.
func WindowPosition(v Value) (int64, int64, error) {
	if err := v.Validate(); err != nil {
		return 0, 0, err
	}
	if v.Kind != ObjectValue || len(v.Object) != 2 {
		return 0, 0, argumentError("position requires exactly x and y integer logical points")
	}
	x, xok := v.Object["x"]
	y, yok := v.Object["y"]
	if !xok || !yok || x.Kind != NumberValue || y.Kind != NumberValue || x.Number < -32768 || x.Number > 32767 || y.Number < -32768 || y.Number > 32767 {
		return 0, 0, argumentError("position requires bounded x and y integer logical points")
	}
	return x.Number, y.Number, nil
}

// ValidateLiteralText bounds selected-text writes and private equality probes.
func ValidateLiteralText(value string) error {
	if len(value) > 65536 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return argumentError("bounded valid native literal text required")
	}
	return nil
}
