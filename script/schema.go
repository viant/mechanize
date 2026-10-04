package script

import (
	"github.com/viant/mechanize/model"
	"reflect"
	"strings"
)

// Schema returns the closed JSON Schema for the shared executable plan.
// Recursive typed values and selectors retain their discriminated alternatives.
func Schema() map[string]any {
	object := func(props map[string]any, required ...string) map[string]any {
		result := map[string]any{"type": "object", "additionalProperties": false, "properties": props}
		if len(required) > 0 {
			result["required"] = required
		}
		return result
	}
	str := map[string]any{"type": "string"}
	integer := map[string]any{"type": "integer"}
	boolean := map[string]any{"type": "boolean"}
	ref := func(name string) map[string]any { return map[string]any{"$ref": "#/$defs/" + name} }
	enum := func(values ...string) map[string]any { return map[string]any{"type": "string", "enum": values} }
	array := func(items any) map[string]any { return map[string]any{"type": "array", "items": items} }
	values := map[string]any{"type": "object", "additionalProperties": ref("value")}
	kind := func(k string) map[string]any { return map[string]any{"const": k} }
	value := map[string]any{"oneOf": []any{
		object(map[string]any{"kind": kind("string"), "string": str}, "kind"),
		object(map[string]any{"kind": kind("number"), "number": integer}, "kind"),
		object(map[string]any{"kind": kind("boolean"), "boolean": boolean}, "kind"),
		object(map[string]any{"kind": kind("duration"), "number": map[string]any{"type": "integer", "minimum": 1, "maximum": 3600000}}, "kind", "number"),
		object(map[string]any{"kind": kind("reference"), "expected": enum("string", "number", "boolean", "duration", "array", "object"), "ref": map[string]any{"type": "string", "pattern": "^(input|artifact|run|binding|step)\\..+$"}}, "kind", "ref"),
		object(map[string]any{"kind": kind("array"), "array": array(ref("value"))}, "kind"),
		object(map[string]any{"kind": kind("object"), "object": values}, "kind"),
	}}
	surface := map[string]any{"oneOf": []any{object(map[string]any{"kind": kind("native"), "bundleId": str, "processId": map[string]any{"type": "integer", "minimum": 1, "maximum": 2147483647}, "processStartToken": map[string]any{"type": "string", "maxLength": 27, "pattern": `^[1-9][0-9]{0,19}:(0|[1-9][0-9]{0,5})$`}}, "kind", "bundleId"), object(map[string]any{"kind": kind("web"), "origin": str, "title": str, "tabId": str}, "kind")}}
	surface["oneOf"].([]any)[0].(map[string]any)["dependentRequired"] = map[string]any{"processId": []string{"processStartToken"}, "processStartToken": []string{"processId"}}
	locator := object(map[string]any{"strategy": enum("role", "name", "id", "testId", "label", "text"), "value": ref("value"), "name": ref("value"), "exact": boolean}, "strategy", "value", "exact")
	scope := object(map[string]any{"nativeRoot": enum("menuBar", "focusedElement"), "window": values, "frame": values})
	selector := object(map[string]any{"surface": ref("surface"), "scope": ref("scope"), "locator": ref("locator"), "ancestor": ref("selector"), "cardinality": enum("one", "all", "nth"), "limit": integer, "index": integer, "order": enum("tree", "document")}, "surface", "scope", "cardinality")
	assertion := object(map[string]any{"matcher": enum("toBeVisible", "toBeEnabled", "toHaveText", "toHaveValue", "toBeChecked"), "not": boolean, "expected": ref("value")}, "matcher", "not")
	span := object(map[string]any{"offset": integer, "line": integer, "column": integer}, "offset", "line", "column")
	step := object(map[string]any{"id": str, "action": enum(actionNames()...), "target": ref("selector"), "arguments": values, "timeoutMs": map[string]any{"type": "integer", "minimum": 1, "maximum": 3600000}, "effect": object(map[string]any{"class": enum("readOnly", "externalNonIdempotent")}, "class"), "assertion": ref("assertion"), "bind": str, "source": ref("source")}, "id", "action", "target", "arguments", "timeoutMs", "effect", "source")
	binding := object(map[string]any{"name": str, "type": enum("app", "page", "window", "frame", "locator", "value"), "selector": ref("selector"), "value": ref("value")}, "name", "type")
	root := object(map[string]any{"schemaVersion": map[string]any{"const": 1}, "steps": array(ref("step")), "bindings": array(ref("binding"))}, "schemaVersion", "steps", "bindings")
	defs := map[string]any{"value": value, "surface": surface, "scope": scope, "locator": locator, "selector": selector, "assertion": assertion, "source": span, "step": step, "binding": binding}
	for _, name := range []string{"name", "inputs", "surfaces", "artifacts", "objective", "goal", "constraints", "recovery", "requires", "checkpoints"} {
		typ := reflect.TypeOf(model.Plan{})
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if strings.Split(field.Tag.Get("json"), ",")[0] == name {
				root["properties"].(map[string]any)[name] = typeSchema(field.Type, defs)
			}
		}
	}
	for _, name := range []string{"semanticsProfile", "precondition", "postcondition", "checkpoint", "resultType", "purpose"} {
		typ := reflect.TypeOf(model.Step{})
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if strings.Split(field.Tag.Get("json"), ",")[0] == name {
				step["properties"].(map[string]any)[name] = typeSchema(field.Type, defs)
			}
		}
	}
	goal := defs["WorkflowGoal"].(map[string]any)["properties"].(map[string]any)
	goal["description"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 4000}
	goal["successCriteria"] = map[string]any{"type": "array", "maxItems": 16, "items": map[string]any{"type": "string", "minLength": 1, "maxLength": 1000}}
	step["properties"].(map[string]any)["purpose"] = map[string]any{"type": "string", "maxLength": 1000}
	effect := step["properties"].(map[string]any)["effect"].(map[string]any)["properties"].(map[string]any)
	effect["businessKey"] = values
	effect["reconcile"] = typeSchema(reflect.TypeOf((*model.Predicate)(nil)), defs)
	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	root["$defs"] = defs
	return root
}
func (Registry) Schema() map[string]any { return Schema() }

func actionNames() []string {
	var names []string
	for _, a := range model.Actions() {
		names = append(names, a.Action)
	}
	return names
}
func typeSchema(t reflect.Type, defs map[string]any) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	known := map[string]string{"Value": "value", "Surface": "surface", "Selector": "selector", "Assertion": "assertion"}
	if name, ok := known[t.Name()]; ok {
		return map[string]any{"$ref": "#/$defs/" + name}
	}
	switch t.Kind() {
	case reflect.String:
		if t == reflect.TypeOf(model.ValueKind("")) {
			return map[string]any{"type": "string", "enum": []string{"string", "number", "boolean", "duration", "array", "object"}}
		}
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": typeSchema(t.Elem(), defs)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": typeSchema(t.Elem(), defs)}
	case reflect.Struct:
		name := t.Name()
		if _, ok := defs[name]; ok {
			return map[string]any{"$ref": "#/$defs/" + name}
		}
		props := map[string]any{}
		entry := map[string]any{"type": "object", "additionalProperties": false, "properties": props}
		defs[name] = entry
		var required []string
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			key := strings.Split(tag, ",")[0]
			if key == "" || key == "-" {
				continue
			}
			props[key] = typeSchema(f.Type, defs)
			if !strings.Contains(tag, "omitempty") {
				required = append(required, key)
			}
		}
		if len(required) > 0 {
			entry["required"] = required
		}
		return map[string]any{"$ref": "#/$defs/" + name}
	}
	return map[string]any{}
}

// EnvelopeSchema extends the canonical plan schema with command-source steps.
// Commands must normalize to one step before Plan.Validate can succeed.
func EnvelopeSchema() map[string]any {
	root := Schema()
	defs := root["$defs"].(map[string]any)
	canonical := defs["step"]
	defs["canonicalStep"] = canonical
	props := map[string]any{"id": map[string]any{"type": "string"}, "command": map[string]any{"type": "string"}}
	stepProps := canonical.(map[string]any)["properties"].(map[string]any)
	for _, k := range []string{"semanticsProfile", "precondition", "postcondition", "checkpoint", "timeoutMs", "effect", "purpose"} {
		props[k] = stepProps[k]
	}
	defs["step"] = map[string]any{"oneOf": []any{map[string]any{"$ref": "#/$defs/canonicalStep"}, map[string]any{"type": "object", "additionalProperties": false, "properties": props, "required": []string{"id", "command"}}}}
	return root
}
