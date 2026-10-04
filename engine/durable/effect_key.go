package durable

import (
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/model"
	"strings"
)

// effectBusinessKey preserves the resolved, typed business entity identity.
// Attempt/effect IDs separately fence run/plan/step dispatch identity.
func effectBusinessKey(plan model.Plan, step model.Step, values map[string]model.Value) (string, error) {
	if len(step.Effect.BusinessKey) == 0 {
		if step.Effect.Class == model.ExternalNonIdempotent {
			return "", errors.New("externalNonIdempotent requires an exact effect.businessKey; use a JSON/YAML workflow envelope declaring typed business key fields")
		}
		return "", nil
	}
	if len(step.Effect.BusinessKey) > 64 {
		return "", errors.New("business key exceeds 64 fields")
	}
	sensitive := map[string]bool{}
	for name, definition := range plan.Inputs {
		if definition.Sensitive {
			sensitive["input."+name] = true
		}
	}
	// Follow declared binding provenance, including outputs whose arguments use
	// sensitive inputs. Live concrete values must not erase known sensitivity.
	for iteration := 0; iteration <= len(plan.Bindings)+len(plan.Steps); iteration++ {
		changed := false
		for _, binding := range plan.Bindings {
			if binding.Value != nil && sensitiveValue(*binding.Value, sensitive) && !sensitive["binding."+binding.Name] {
				sensitive["binding."+binding.Name] = true
				changed = true
			}
		}
		for _, source := range plan.Steps {
			if source.Bind != "" && !sensitive["binding."+source.Bind] {
				for _, argument := range source.Arguments {
					if sensitiveValue(argument, sensitive) {
						sensitive["binding."+source.Bind] = true
						changed = true
						break
					}
				}
			}
		}
		if !changed {
			break
		}
	}
	resolved := make(map[string]model.Value, len(step.Effect.BusinessKey))
	for name, value := range step.Effect.BusinessKey {
		if name == "" || strings.TrimSpace(name) != name || len(name) > 128 {
			return "", errors.New("business key field name is invalid")
		}
		if sensitiveResolvedValue(value, sensitive, values, map[string]bool{}, 0) {
			return "", errors.New("business key references a sensitive input; use a non-secret business entity identifier")
		}
		actual, err := model.ResolveValue(value, values)
		if err != nil {
			return "", errors.New("business key typed reference could not be resolved")
		}
		if actual.Kind == model.StringValue && actual.String == "" {
			return "", errors.New("business key string cannot be empty")
		}
		resolved[name] = actual
	}
	raw, err := json.Marshal(resolved) // encoding/json sorts object keys deterministically.
	if err != nil {
		return "", errors.New("business key cannot be encoded")
	}
	if len(raw) > 8192 {
		return "", errors.New("business key exceeds 8192 bytes")
	}
	return string(raw), nil
}
func sensitiveValue(value model.Value, sensitive map[string]bool) bool {
	if value.Kind == model.ReferenceValue {
		return sensitive[value.Ref]
	}
	for _, item := range value.Array {
		if sensitiveValue(item, sensitive) {
			return true
		}
	}
	for _, item := range value.Object {
		if sensitiveValue(item, sensitive) {
			return true
		}
	}
	return false
}

func sensitiveResolvedValue(value model.Value, sensitive map[string]bool, values map[string]model.Value, seen map[string]bool, depth int) bool {
	if depth > 64 {
		return true
	}
	if value.Kind == model.ReferenceValue {
		if sensitive[value.Ref] {
			return true
		}
		if seen[value.Ref] {
			return true
		}
		seen[value.Ref] = true
		next, exists := values[value.Ref]
		result := exists && sensitiveResolvedValue(next, sensitive, values, seen, depth+1)
		delete(seen, value.Ref)
		return result
	}
	for _, item := range value.Array {
		if sensitiveResolvedValue(item, sensitive, values, seen, depth+1) {
			return true
		}
	}
	for _, item := range value.Object {
		if sensitiveResolvedValue(item, sensitive, values, seen, depth+1) {
			return true
		}
	}
	return false
}
