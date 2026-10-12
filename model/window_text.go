package model

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type WindowTextInput struct {
	WindowID                                    uint32
	Text, FocusRole, FocusIdentifier, FocusName string
}

func ValidateWindowText(v Value) error {
	if v.Kind != ObjectValue || len(v.Object) != 5 {
		return argumentError("window text requires windowId, text, focusRole, focusIdentifier and focusName")
	}
	for name, kind := range map[string]ValueKind{"windowId": NumberValue, "text": StringValue, "focusRole": StringValue, "focusIdentifier": StringValue, "focusName": StringValue} {
		x, ok := v.Object[name]
		if !ok {
			return argumentError("missing window text field")
		}
		if x.Kind == ReferenceValue {
			if x.Expected != kind {
				return argumentError("window text reference type mismatch")
			}
			continue
		}
		if x.Kind != kind {
			return argumentError("invalid window text field type")
		}
		if kind == NumberValue {
			if x.Number < 1 || x.Number > 4294967295 {
				return argumentError("positive uint32 windowId required")
			}
			continue
		}
		max := 256
		if name == "text" {
			max = 4096
		}
		if len(x.String) > max || !utf8.ValidString(x.String) {
			return argumentError("bounded UTF-8 window text required")
		}
		for _, r := range x.String {
			if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
				return argumentError("window text cannot contain control characters; use explicit key actions")
			}
		}
		if (name == "text" || name == "focusRole") && x.String == "" {
			return argumentError("nonempty text and focus role required")
		}
	}
	role := v.Object["focusRole"]
	if role.Kind == StringValue && role.String != "AXTextField" && role.String != "AXTextArea" && role.String != "AXLayoutArea" && role.String != "AXSplitGroup" {
		return argumentError("unsupported focused text role")
	}
	id, name := v.Object["focusIdentifier"], v.Object["focusName"]
	if id.Kind == StringValue && name.Kind == StringValue && id.String == "" && name.String == "" {
		return argumentError("exact focused identifier or name required")
	}
	for _, field := range []Value{id, name} {
		if field.Kind == StringValue {
			for _, marker := range []string{"password", "credential", "secret", "token", "securetextfield"} {
				if strings.Contains(strings.ToLower(field.String), marker) {
					return argumentError("protected text target unsupported")
				}
			}
		}
	}
	return nil
}

func WindowText(v Value) (WindowTextInput, error) {
	if err := ValidateWindowText(v); err != nil {
		return WindowTextInput{}, err
	}
	for _, x := range v.Object {
		if x.Kind == ReferenceValue {
			return WindowTextInput{}, argumentError("resolved window text required")
		}
	}
	return WindowTextInput{WindowID: uint32(v.Object["windowId"].Number), Text: v.Object["text"].String, FocusRole: v.Object["focusRole"].String, FocusIdentifier: v.Object["focusIdentifier"].String, FocusName: v.Object["focusName"].String}, nil
}
