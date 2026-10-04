package model

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ResolveValue resolves a typed reference without ever constructing command source.
func ResolveValue(v Value, bindings map[string]Value) (Value, error) {
	if err := v.Validate(); err != nil {
		return Value{}, err
	}
	budget := 100000
	return resolveValue(v, bindings, map[string]bool{}, 0, &budget)
}
func resolveValue(v Value, bindings map[string]Value, seen map[string]bool, depth int, budget *int) (Value, error) {
	*budget--
	if *budget < 0 {
		return Value{}, fmt.Errorf("resolved value exceeds 100000 nodes")
	}
	if depth > 64 {
		return Value{}, fmt.Errorf("value nesting exceeds 64")
	}
	if v.Kind == ReferenceValue {
		if seen[v.Ref] {
			return Value{}, fmt.Errorf("cyclic reference %s", v.Ref)
		}
		next, ok := bindings[v.Ref]
		if !ok {
			return Value{}, fmt.Errorf("unresolved reference %s", v.Ref)
		}
		if err := next.Validate(); err != nil {
			return Value{}, err
		}
		seen[v.Ref] = true
		result, err := resolveValue(next, bindings, seen, depth+1, budget)
		delete(seen, v.Ref)
		if err == nil && v.Expected != "" && result.Kind != v.Expected {
			return Value{}, fmt.Errorf("reference %s requires %s, got %s", v.Ref, v.Expected, result.Kind)
		}
		return result, err
	}
	if v.Kind == ArrayValue {
		items := make([]Value, len(v.Array))
		for i, x := range v.Array {
			resolved, err := resolveValue(x, bindings, seen, depth+1, budget)
			if err != nil {
				return Value{}, err
			}
			items[i] = resolved
		}
		v.Array = items
	}
	if v.Kind == ObjectValue {
		fields := make(map[string]Value, len(v.Object))
		for k, x := range v.Object {
			resolved, err := resolveValue(x, bindings, seen, depth+1, budget)
			if err != nil {
				return Value{}, err
			}
			fields[k] = resolved
		}
		v.Object = fields
	}
	return v, nil
}
func (v Value) Validate() error { return v.validate(0) }
func (v Value) validate(depth int) error {
	if len(v.Array) > 10000 || len(v.Object) > 10000 || len(v.String) > 1<<20 {
		return fmt.Errorf("value exceeds size limit")
	}
	if depth > 64 {
		return fmt.Errorf("value nesting exceeds 64")
	}
	if v.Expected != "" && (v.Kind != ReferenceValue || !validValueKind(v.Expected)) {
		return fmt.Errorf("expected type only allowed on reference")
	}
	if v.Kind != StringValue && v.String != "" || v.Kind != NumberValue && v.Kind != DurationValue && v.Number != 0 || v.Kind != BoolValue && v.Bool || v.Kind != ReferenceValue && v.Ref != "" || v.Kind != ArrayValue && v.Array != nil || v.Kind != ObjectValue && v.Object != nil {
		return fmt.Errorf("fields do not match value kind %s", v.Kind)
	}
	switch v.Kind {
	case ArrayValue:
		for _, x := range v.Array {
			if err := x.validate(depth + 1); err != nil {
				return err
			}
		}
	case ObjectValue:
		for _, x := range v.Object {
			if err := x.validate(depth + 1); err != nil {
				return err
			}
		}
	case StringValue, NumberValue, BoolValue:
	case DurationValue:
		if v.Number <= 0 || v.Number > 3600000 {
			return fmt.Errorf("invalid duration")
		}
	case ReferenceValue:
		if !(strings.HasPrefix(v.Ref, "input.") || strings.HasPrefix(v.Ref, "artifact.") || strings.HasPrefix(v.Ref, "run.") || strings.HasPrefix(v.Ref, "binding.") || strings.HasPrefix(v.Ref, "step.")) {
			return fmt.Errorf("invalid reference namespace")
		}
	default:
		return fmt.Errorf("unknown value kind %q", v.Kind)
	}
	return nil
}
func (s Selector) Validate() error { return s.validate(0) }
func (s Selector) validate(depth int) error {
	if depth > 64 {
		return fmt.Errorf("selector nesting exceeds 64")
	}
	if s.Scope.NativeRoot != "" {
		if (s.Scope.NativeRoot != "menuBar" && s.Scope.NativeRoot != "focusedElement") || s.Surface.Kind != "native" || len(s.Scope.Window) != 0 || len(s.Scope.Frame) != 0 {
			return fmt.Errorf("native root must be menuBar or focusedElement without window/frame scopes")
		}
	}
	switch s.Cardinality {
	case "one":
		if s.Limit != 0 || s.Index != nil {
			return fmt.Errorf("strict one cannot carry plural options")
		}
	case "all":
		if s.Limit < 1 || s.Limit > 1000 || s.Index != nil {
			return fmt.Errorf("plural read requires limit 1..1000")
		}
	case "nth":
		if s.Index == nil || *s.Index < 0 || *s.Index > 999 || s.Order == "" || s.Limit != 0 {
			return fmt.Errorf("nth requires explicit ordering and index 0..999")
		}
	default:
		return fmt.Errorf("unsupported cardinality")
	}
	if s.Order != "" && s.Order != "document" && s.Order != "tree" {
		return fmt.Errorf("unsupported ordering")
	}
	if s.Surface.Kind == "native" && s.Order == "document" || s.Surface.Kind == "web" && s.Order == "tree" {
		return fmt.Errorf("ordering does not match surface")
	}

	switch s.Surface.Kind {
	case "native":
		if s.Surface.BundleID == "" {
			return fmt.Errorf("native selector needs bundle ID")
		}
	case "web":
		if s.Surface.Origin == "" && s.Surface.TabID == "" {
			return fmt.Errorf("web selector needs origin or tab ID")
		}
	default:
		return fmt.Errorf("unknown surface")
	}
	if s.Surface.Kind == "native" && (s.Surface.Origin != "" || s.Surface.TabID != "" || s.Surface.Title != "" || len(s.Scope.Frame) != 0) {
		return fmt.Errorf("web identity or frame on native surface")
	}
	if err := s.Surface.ValidateProcessIdentity(); err != nil {
		return err
	}
	if s.Surface.Kind == "web" && (s.Surface.BundleID != "" || len(s.Scope.Window) != 0) {
		return fmt.Errorf("native identity or window on web surface")
	}
	if s.Locator != nil {
		if s.Locator.Value.Kind != StringValue && s.Locator.Value.Kind != ReferenceValue {
			return fmt.Errorf("locator value must be string or reference")
		}
		if s.Locator.Name != nil && (s.Locator.Strategy != "role" || s.Locator.Name.Kind != StringValue && s.Locator.Name.Kind != ReferenceValue) {
			return fmt.Errorf("role name must be string or reference")
		}
		switch s.Locator.Strategy {
		case "role", "name", "id", "testId", "label", "text":
		default:
			return fmt.Errorf("unknown locator strategy")
		}
		if err := s.Locator.Value.Validate(); err != nil {
			return err
		}
		if s.Locator.Name != nil {
			if err := s.Locator.Name.Validate(); err != nil {
				return err
			}
		}
	}
	for _, options := range []map[string]Value{s.Scope.Window, s.Scope.Frame} {
		for _, v := range options {
			if err := v.Validate(); err != nil {
				return err
			}
		}
	}
	for _, options := range []struct {
		values  map[string]Value
		allowed map[string]bool
	}{{s.Scope.Window, map[string]bool{"title": true, "role": true, "documentKey": true}}, {s.Scope.Frame, map[string]bool{"id": true, "name": true}}} {
		for k, v := range options.values {
			if !options.allowed[k] || v.Kind != StringValue && v.Kind != ReferenceValue {
				return fmt.Errorf("invalid scope option %s", k)
			}
		}
	}
	if s.Ancestor != nil {
		if s.Ancestor.Surface != s.Surface {
			return fmt.Errorf("ancestor crosses surfaces")
		}
		if s.Ancestor.Scope.NativeRoot != s.Scope.NativeRoot {
			return fmt.Errorf("ancestor crosses native root scope")
		}
		return s.Ancestor.validate(depth + 1)
	}
	return nil
}

var nativeBundleIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$`)

func (s Step) Validate() error {
	if s.ID == "" || s.Command != "" {
		return fmt.Errorf("step needs ID and normalized action")
	}
	if err := s.Target.Validate(); err != nil {
		return err
	}
	if s.Action == "element.pressSessionKey" && (s.Target.Surface.Kind != "native" || s.Target.Surface.ProcessID <= 0 || s.Target.Surface.ProcessStartToken == "") {
		return fmt.Errorf("session keyboard requires an exact native PID and process birth")
	}
	if s.TimeoutMs <= 0 || s.TimeoutMs > 3600000 {
		return fmt.Errorf("invalid timeout")
	}
	a, ok := ActionByName(s.Action)
	if !ok {
		return fmt.Errorf("unsupported action %q", s.Action)
	}
	effect := ExternalNonIdempotent
	if a.ReadOnly {
		effect = ReadOnly
	}
	if s.Effect.Class != effect {
		return fmt.Errorf("action %s requires conservative effect %s", s.Action, effect)
	}
	if s.Action == "app.activate" && len(s.Effect.BusinessKey) == 0 {
		return fmt.Errorf("app.activate requires a business key")
	}
	if s.Action == "app.open" && s.Target.Surface.ProcessID != 0 {
		return fmt.Errorf("app.open cannot target an existing process")
	}
	if s.Action == "app.open" || s.Action == "app.activate" {
		if s.Target.Surface.Kind != "native" || len(s.Target.Surface.BundleID) > 255 || !nativeBundleIdentifier.MatchString(s.Target.Surface.BundleID) || s.Target.Locator != nil || s.Target.Ancestor != nil || s.Target.Scope.NativeRoot != "" || len(s.Target.Scope.Window) != 0 || len(s.Target.Scope.Frame) != 0 || s.Target.Cardinality != "one" || s.Target.Order != "" {
			return fmt.Errorf("app.open requires one exact native bundle without element or window selectors")
		}
		if s.Bind != "" || s.ResultType != "" {
			return fmt.Errorf("app.open cannot bind a business result")
		}
	}
	if s.Target.Scope.NativeRoot != "" && s.Target.Locator == nil {
		return fmt.Errorf("native root actions require an explicit locator")
	}
	if s.Action != "expect" && s.Action != "app.open" && s.Action != "app.activate" && s.Action != "window.pressSessionKey" && s.Action != "window.clickFrame" && s.Target.Locator == nil {
		return fmt.Errorf("element action needs locator")
	}
	if s.Target.Cardinality == "all" && s.Action != "element.read" {
		return fmt.Errorf("plural targets only permitted for reads")
	}
	if a.Argument == "" && len(s.Arguments) != 0 || a.Argument != "" && len(s.Arguments) != 1 {
		return fmt.Errorf("invalid action arguments")
	}
	for k, v := range s.Arguments {
		if k != a.Argument || v.Kind != a.ArgumentType && v.Kind != ReferenceValue {
			return fmt.Errorf("invalid argument %s", k)
		}
		if err := v.Validate(); err != nil {
			return err
		}
		if v.Kind == ReferenceValue && v.Expected != "" && v.Expected != a.ArgumentType {
			return fmt.Errorf("reference argument type mismatch")
		}
	}
	if s.Action == "window.moveTo" {
		if s.Target.Surface.Kind != "native" || s.Target.Surface.ProcessID <= 0 || s.Target.Surface.ProcessStartToken == "" || s.Target.Cardinality != "one" || s.Target.Scope.NativeRoot != "" || len(s.Target.Scope.Window) != 0 || len(s.Target.Scope.Frame) != 0 || s.Target.Ancestor != nil {
			return fmt.Errorf("window.moveTo requires one exact native process target")
		}
		if v := s.Arguments["position"]; v.Kind != ReferenceValue {
			if _, _, err := WindowPosition(v); err != nil {
				return err
			}
		}
	}
	if s.Action == "element.replaceText" {
		if s.Target.Surface.Kind != "native" || s.Target.Surface.ProcessID <= 0 || s.Target.Surface.ProcessStartToken == "" || s.Target.Cardinality != "one" {
			return fmt.Errorf("replaceText requires one exact native process target")
		}
		if value := s.Arguments["value"]; value.Kind == StringValue {
			if err := ValidateLiteralText(value.String); err != nil {
				return err
			}
		}
	}
	if s.Action == "window.pressSessionKey" {
		if s.Target.Surface.Kind != "native" || s.Target.Surface.ProcessID <= 0 || s.Target.Surface.ProcessStartToken == "" || s.Target.Locator != nil || s.Target.Ancestor != nil || s.Target.Cardinality != "one" || s.Target.Order != "" || s.Target.Scope.NativeRoot != "" || len(s.Target.Scope.Window) != 0 || len(s.Target.Scope.Frame) != 0 {
			return fmt.Errorf("window keyboard requires one exact native process without AX selectors/scopes")
		}
		if value := s.Arguments["windowKey"]; value.Kind != ReferenceValue {
			if err := ValidateWindowSessionKey(value); err != nil {
				return err
			}
		}
	}
	if s.Action == "window.clickFrame" {
		if s.Target.Surface.Kind != "native" || s.Target.Surface.ProcessID <= 0 || s.Target.Surface.ProcessStartToken == "" || s.Target.Locator != nil || s.Target.Ancestor != nil || s.Target.Cardinality != "one" || s.Target.Order != "" || s.Target.Scope.NativeRoot != "" || len(s.Target.Scope.Window) != 0 || len(s.Target.Scope.Frame) != 0 || s.Bind != "" || s.ResultType != "" {
			return fmt.Errorf("window frame click requires one exact native process without AX selectors/scopes or result binding")
		}
		if value := s.Arguments["frameClick"]; value.Kind != ReferenceValue {
			if err := ValidateWindowFrameClick(value); err != nil {
				return err
			}
		}
	}
	if s.Action == "element.read" {
		result := StringValue
		if s.Arguments["attribute"].String == "checked" || s.Arguments["attribute"].String == "focused" || s.Arguments["attribute"].String == "enabled" {
			result = BoolValue
		}
		if s.Target.Cardinality == "all" {
			result = ArrayValue
		}
		if s.ResultType != "" && s.ResultType != result {
			return fmt.Errorf("read result type mismatch")
		}
		v := s.Arguments["attribute"]
		if v.Kind != StringValue {
			return fmt.Errorf("read needs literal attribute")
		}
		switch v.String {
		case "text", "value", "name", "checked":
		case "staticText", "focused", "enabled", "identifier", "role":
			if s.Target.Surface.Kind != "native" {
				return fmt.Errorf("%s requires a native surface", v.String)
			}
		default:
			return fmt.Errorf("invalid read attribute")
		}
	}
	if s.Action == "expect" {
		if err := validateAssertion(s.Assertion, s.Target.Locator != nil); err != nil {
			return err
		}
	} else if s.Assertion != nil {
		return fmt.Errorf("assertion only valid on expect")
	}
	for _, p := range []*Predicate{s.Precondition, s.Postcondition, s.Effect.Reconcile} {
		if p != nil {
			if err := p.Validate(); err != nil {
				return err
			}
		}
	}
	for _, v := range s.Effect.BusinessKey {
		if err := v.Validate(); err != nil {
			return err
		}
	}
	if s.Effect.Reconcile != nil && len(s.Effect.BusinessKey) == 0 {
		return fmt.Errorf("reconciliation needs business key")
	}
	if s.Checkpoint != nil {
		return s.Checkpoint.Validate()
	}
	return nil
}
func validateAssertion(a *Assertion, hasLocator bool) error {
	if a == nil {
		return fmt.Errorf("assertion required")
	}
	switch a.Matcher {
	case "toBeVisible", "toBeEnabled", "toBeChecked":
		if a.Matcher == "toBeChecked" && !hasLocator {
			return fmt.Errorf("checked assertion requires locator")
		}
		if a.Expected != nil {
			return fmt.Errorf("unexpected assertion value")
		}
	case "toHaveText", "toHaveValue":
		if a.Expected == nil || !hasLocator {
			return fmt.Errorf("value assertion needs target and expected")
		}
		if a.Expected.Kind != StringValue && a.Expected.Kind != ReferenceValue {
			return fmt.Errorf("expected value must be string")
		}
		return a.Expected.Validate()
	default:
		return fmt.Errorf("unknown matcher")
	}
	return nil
}
func validValueKind(k ValueKind) bool {
	switch k {
	case StringValue, NumberValue, BoolValue, DurationValue, ArrayValue, ObjectValue:
		return true
	}
	return false
}
func (p Plan) Validate() error {
	if len(p.Steps) > 10000 || len(p.Bindings) > 10000 {
		return fmt.Errorf("plan exceeds 10000 steps or bindings")
	}
	if p.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema version")
	}
	names := map[string]bool{}
	for _, b := range p.Bindings {
		if !identifier(b.Name) || names[b.Name] {
			return fmt.Errorf("invalid or duplicate binding %s", b.Name)
		}
		names[b.Name] = true
		if b.Type == "value" {
			if b.Value == nil || b.Selector != nil {
				return fmt.Errorf("value binding needs value")
			}
			if err := b.Value.Validate(); err != nil {
				return err
			}
		} else {
			switch b.Type {
			case "app", "page", "window", "frame", "locator":
			default:
				return fmt.Errorf("invalid binding type")
			}
			if b.Selector == nil || b.Value != nil {
				return fmt.Errorf("scope binding needs selector")
			}
			if err := b.Selector.Validate(); err != nil {
				return err
			}
		}
	}
	seen := map[string]bool{}
	for _, s := range p.Steps {
		if seen[s.ID] {
			return fmt.Errorf("duplicate step ID %s", s.ID)
		}
		seen[s.ID] = true
		if err := s.Validate(); err != nil {
			return fmt.Errorf("step %s: %w", s.ID, err)
		}
	}
	return p.validateMetadata()
}

// ValidateProcessIdentity accepts only a complete native libproc fingerprint.
// The canonical seconds:microseconds token never permits PID-only targeting.
func (s Surface) ValidateProcessIdentity() error {
	if s.ProcessID == 0 && s.ProcessStartToken == "" {
		return nil
	}
	if s.Kind != "native" || s.ProcessID <= 0 || int64(s.ProcessID) > 2147483647 || len(s.ProcessStartToken) > 27 || !ValidProcessStartToken(s.ProcessStartToken) {
		return fmt.Errorf("exact native process requires positive PID and canonical start token")
	}
	return nil
}

var nativeProcessStartToken = regexp.MustCompile(`^[1-9][0-9]{0,19}:(0|[1-9][0-9]{0,5})$`)

func ValidProcessStartToken(token string) bool {
	if len(token) > 27 || !nativeProcessStartToken.MatchString(token) {
		return false
	}
	parts := strings.Split(token, ":")
	_, err := strconv.ParseUint(parts[0], 10, 64)
	return err == nil
}
