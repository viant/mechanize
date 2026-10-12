package model

import (
	"net/url"
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
		{Action: "browser.activateTab", Capability: "browser.activateTab"},
		{Action: "browser.openOrigin", Method: "openOrigin", Capability: "browser.openOrigin"},
		{Action: "browser.navigate", Method: "navigate", Argument: "url", ArgumentType: StringValue, Capability: "browser.navigate"},
		{Action: "browser.activate", Method: "activateTab", Capability: "browser.activate"},
		{Action: "app.quit", Method: "quit", Capability: "appQuit"},
		{Action: "app.activate", Method: "activate", Capability: "appActivation"},
		{Action: "app.open", Method: "open", Capability: "appLaunch"},
		{Action: "window.typeText", Method: "typeWindowText", Argument: "windowText", ArgumentType: ObjectValue, Capability: "windowSessionText"},
		{Action: "window.pressSessionKey", Method: "pressWindowKey", Argument: "windowKey", ArgumentType: ObjectValue, Capability: "windowSessionKeyboard"},
		{Action: "window.clickFrame", Method: "clickWindowFrame", Argument: "frameClick", ArgumentType: ObjectValue, Capability: "windowFrameClick"},
		{Action: "window.moveTo", Method: "moveTo", Argument: "position", ArgumentType: ObjectValue, Capability: "windowPosition"},
		{Action: "element.focus", Method: "focus", Capability: "targetedFocus"},
		{Action: "element.press", Method: "click", Capability: "semanticPress"},
		{Action: "element.showMenu", Method: "showMenu", Capability: "semanticMenu"},
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
	if name == "" {
		return ActionDefinition{}, false
	}
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
	if s.Action == "browser.navigate" {
		if _, err := NavigationOrigin(out["url"].String); err != nil {
			return nil, err
		}
	}
	if s.Action == "window.moveTo" {
		if _, _, err := WindowPosition(out["position"]); err != nil {
			return nil, err
		}
	}
	if s.Action == "window.typeText" {
		if _, err := WindowText(out["windowText"]); err != nil {
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

// NavigationOrigin validates an ordinary destination; consent is checked separately.
func NavigationOrigin(value string) (string, error) {
	u, e := url.Parse(value)
	if e != nil || len(value) > 8192 || u == nil || u.User != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || strings.ContainsAny(value, "\\\r\n\x00") {
		return "", argumentError("ordinary HTTP(S) navigation URL required")
	}
	for key := range u.Query() {
		lower := strings.ToLower(key)
		for _, word := range []string{"password", "token", "secret", "credential"} {
			if strings.Contains(lower, word) {
				return "", argumentError("credential URL forbidden")
			}
		}
	}
	return u.Scheme + "://" + u.Host, nil
}

// ExactHTTPOrigin admits only a public origin, never a navigation path or input.
func ExactHTTPOrigin(value string) bool {
	u, e := url.Parse(value)
	return e == nil && len(value) <= 2048 && u.Hostname() != "" && u.User == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Path == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && u.Scheme+"://"+u.Host == value && !strings.ContainsAny(value, "*\\\r\n\x00")
}

// OpaqueTabHandle is routing metadata from the enrolled extension, not a URL.
func OpaqueTabHandle(value string) bool {
	if len(value) > 300 {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts[:2] {
		if len(part) < 1 || len(part) > 128 {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	if len(parts[2]) < 1 || len(parts[2]) > 16 || parts[2][0] == '0' {
		return false
	}
	for _, c := range parts[2] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// OpenOriginReason is a closed transport/receipt vocabulary; never error text.
func OpenOriginReason(code string) string {
	switch code {
	case "none", "unsupportedWorker", "permissionRequired", "openOriginChannelUnavailable", "openOriginBusy", "openOriginAuthorityChanged", "openOriginDeadline", "openOriginUnknown", "openOriginRejected", "openOriginUnavailable", "openOriginPending", "authorityChanged", "permissionUnavailable", "windowUnavailable", "receiptCapacity", "unknownEffect", "lifecycleInhibited", "creationUnavailable", "receiptUnavailable", "attemptConflict":
		return code
	}
	return "openOriginUnavailable"
}

// TabActivationReason projects only finite browser activation diagnostics.
func TabActivationReason(code string) string {
	switch code {
	case "none", "unsupportedWorker", "permissionRequired", "tabActivationChannelUnavailable", "tabActivationBusy", "tabActivationAuthorityChanged", "tabActivationDeadline", "tabActivationUnknown", "tabActivationRejected", "tabActivationUnavailable", "tabActivationPending", "authorityChanged", "permissionUnavailable", "windowUnavailable", "receiptCapacity", "unknownEffect", "lifecycleInhibited", "activationUnavailable", "receiptUnavailable", "attemptConflict", "originDenied", "tabUnavailable":
		return code
	}
	return "tabActivationUnavailable"
}
