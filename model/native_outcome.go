package model

import (
	"errors"
	"reflect"
)

// ValidateNativeScopedOutcome preserves an explicitly scoped mutation's native
// root and exact window boundary in its declared comparisons. Reference
// values are checked again by durable admission after workflow inputs resolve.
// This is a narrow boundary check, not full outcome-adapter qualification.
func ValidateNativeScopedOutcome(step Step, values map[string]Value) error {
	if step.Effect.Class == ReadOnly || step.Target.Surface.Kind != "native" {
		return nil
	}
	for _, predicate := range []*Predicate{step.Postcondition, step.Effect.Reconcile} {
		if predicate == nil || predicate.Adapter != "native" || (predicate.Name != "valueEquals" && predicate.Name != "literalValueMatches") {
			continue
		}
		if len(step.Target.Scope.Window) > 0 {
			if err := validateNativeOutcomeWindow(step.Target.Scope.Window, predicate.Inputs, values); err != nil {
				return err
			}
		}
		if step.Target.Scope.NativeRoot == "" {
			continue
		}
		root := predicate.Inputs["nativeRoot"]
		if root.Kind == ReferenceValue {
			if values == nil {
				continue
			}
			resolved, err := ResolveValue(root, values)
			if err != nil {
				return errors.New("native outcome root reference unavailable")
			}
			root = resolved
		}
		actual := ""
		if root.Kind != "" {
			if root.Kind != StringValue {
				return errors.New("native outcome root requires a typed string")
			}
			actual = root.String
		}
		if actual != step.Target.Scope.NativeRoot {
			return errors.New("native outcome must preserve the explicitly scoped original root")
		}
	}
	return nil
}

// Mirror durable admission's exact boundary comparison before reserving input.
// Static references defer to admission, where their values must be available.
func validateNativeOutcomeWindow(original, inputs, values map[string]Value) error {
	declared := map[string]Value{}
	for input, key := range map[string]string{"windowTitle": "title", "windowRole": "role"} {
		if value, ok := inputs[input]; ok {
			declared[key] = value
		}
	}
	resolve := func(boundary map[string]Value) (map[string]Value, bool, error) {
		result := map[string]Value{}
		for key, value := range boundary {
			if value.Kind == ReferenceValue && values == nil {
				return nil, true, nil
			}
			resolved, err := ResolveValue(value, values)
			if err != nil {
				return nil, false, errors.New("native outcome window reference unavailable")
			}
			result[key] = resolved
		}
		return result, false, nil
	}
	left, deferred, err := resolve(original)
	if err != nil || deferred {
		return err
	}
	right, deferred, err := resolve(declared)
	if err != nil || deferred {
		return err
	}
	if !reflect.DeepEqual(left, right) {
		return errors.New("native outcome must preserve the exact original window title and role")
	}
	return nil
}
