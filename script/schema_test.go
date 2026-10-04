package script

import (
	"encoding/json"
	"github.com/xeipuuv/gojsonschema"
	"strings"
	"testing"
)

func TestSchemaClosedRecordsAndUnions(t *testing.T) {
	p, err := DecodeYAML(strings.NewReader(envelopeYAML))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(p)
	var document any
	if err = json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	schema := Schema() // The emitted vocabulary is also supported by this draft-7 validator.
	schema["$schema"] = "http://json-schema.org/draft-07/schema#"
	result, err := gojsonschema.Validate(gojsonschema.NewGoLoader(schema), gojsonschema.NewGoLoader(document))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid() {
		t.Fatalf("valid normalized plan failed schema: %v", result.Errors())
	}
	obj := document.(map[string]any)
	obj["unknown"] = true
	result, err = gojsonschema.Validate(gojsonschema.NewGoLoader(schema), gojsonschema.NewGoLoader(document))
	if err != nil || result.Valid() {
		t.Fatalf("unknown field accepted: %v", err)
	}
	delete(obj, "unknown")
	steps := obj["steps"].([]any)
	step := steps[1].(map[string]any)
	value := step["arguments"].(map[string]any)["value"].(map[string]any)
	value["string"] = "competing literal"
	result, err = gojsonschema.Validate(gojsonschema.NewGoLoader(schema), gojsonschema.NewGoLoader(document))
	if err != nil || result.Valid() {
		t.Fatalf("conflicting value discriminants accepted: %v", err)
	}
}
func TestEnvelopeSchemaCommandFrontend(t *testing.T) {
	schema := EnvelopeSchema()
	schema["$schema"] = "http://json-schema.org/draft-07/schema#"
	doc := map[string]any{"schemaVersion": 1, "bindings": []any{}, "steps": []any{map[string]any{"id": "a", "command": `app("fixture").getById("x").click()`}}}
	result, err := gojsonschema.Validate(gojsonschema.NewGoLoader(schema), gojsonschema.NewGoLoader(doc))
	if err != nil || !result.Valid() {
		t.Fatalf("command frontend schema: %v %v", err, result.Errors())
	}
}
