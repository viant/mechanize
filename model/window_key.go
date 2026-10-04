package model

import (
	"errors"
	"strconv"
	"strings"
)

// ValidateKeyboardChord is the shared closed login-session/targeted chord codec.
func ValidateKeyboardChord(key string) error {
	if key == "" || len(key) > 64 {
		return errors.New("bounded chord required")
	}
	parts := strings.Split(key, "+")
	name := parts[len(parts)-1]
	valid := len(name) == 1 && name[0] >= 'A' && name[0] <= 'Z'
	if len(name) >= 2 && name[0] == 'F' {
		if number, err := strconv.Atoi(name[1:]); err == nil && number >= 1 && number <= 20 && strconv.Itoa(number) == name[1:] {
			valid = true
		}
	}
	for _, candidate := range []string{"Space", "Tab", "Return", "Enter", "Escape", "ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End", "PageUp", "PageDown", "Backspace", "Delete"} {
		valid = valid || name == candidate
	}
	if !valid || len(parts) > 5 {
		return errors.New("unsupported named key")
	}
	seen := map[string]bool{}
	for _, modifier := range parts[:len(parts)-1] {
		if modifier == "Cmd" {
			modifier = "Command"
		}
		if seen[modifier] || modifier != "Command" && modifier != "Shift" && modifier != "Control" && modifier != "Option" {
			return errors.New("invalid modifier")
		}
		seen[modifier] = true
	}
	return nil
}
func ValidateWindowSessionKey(v Value) error {
	if v.Kind != ObjectValue || len(v.Object) != 2 {
		return argumentError("closed windowId and key object required")
	}
	id, idOK := v.Object["windowId"]
	key, keyOK := v.Object["key"]
	if !idOK || !keyOK {
		return argumentError("windowId and key required")
	}
	if id.Kind == ReferenceValue {
		if id.Expected != NumberValue {
			return argumentError("windowId requires typed integer")
		}
	} else if id.Kind != NumberValue || id.Number < 1 || id.Number > 4294967295 {
		return argumentError("windowId requires uint32 integer")
	}
	if key.Kind == ReferenceValue {
		if key.Expected != StringValue {
			return argumentError("key requires typed chord")
		}
	} else if key.Kind != StringValue {
		return argumentError("key requires closed chord")
	} else if err := ValidateKeyboardChord(key.String); err != nil {
		return err
	}
	return nil
}
func WindowSessionKey(v Value) (uint32, string, error) {
	if err := ValidateWindowSessionKey(v); err != nil {
		return 0, "", err
	}
	id, key := v.Object["windowId"], v.Object["key"]
	if id.Kind != NumberValue || key.Kind != StringValue {
		return 0, "", argumentError("resolved windowId and key required")
	}
	return uint32(id.Number), key.String, nil
}
