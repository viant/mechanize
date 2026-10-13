package mcp

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestControllerScriptReadDiagnosticAllowsCorrectionWithoutExecution(t *testing.T) {
	d, id, ctx, dispatches := controllerFixture(t)
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
	source := `web.tab(origin:"https://fixture.test").getById("PRIVATE_SELECTOR_CANARY",exact:true).read("textContent")`
	_, compileErr := script.Compile(source)
	compiler := compileErr.(*script.Error)
	for _, name := range []string{"mechanize_script_validate", "mechanize_script_run", "mechanize_step_run"} {
		args := map[string]any{"source": source}
		if name != "mechanize_script_validate" {
			args["sessionId"], args["clientRequestId"], args["purpose"] = session, "invalid-read-attribute", "Inspect public fixture"
		}
		out := controllerCall(t, d, ctx, id, name, args)
		body := controllerBody(t, out)
		if out.IsError == nil || !*out.IsError || body["code"] != "scriptValidationFailed" || body["validationCode"] != "unsupportedReadAttribute" || body["dispatchState"] != "notDispatched" || body["stage"] != "typecheck" || body["line"] != float64(compiler.Position.Line) || body["column"] != float64(compiler.Position.Column) {
			t.Fatal("controller erased actionable compiler diagnostic", body)
		}
		if !reflect.DeepEqual(body["allowedReadAttributes"], []any{"text", "value", "name", "checked"}) {
			t.Fatal("valid read attributes not supplied")
		}
		wire, _ := json.Marshal(out)
		for _, forbidden := range []string{"PRIVATE_SELECTOR_CANARY", "https://fixture.test", "review local permissions", "textContent"} {
			if strings.Contains(string(wire), forbidden) {
				t.Fatal("diagnostic echoed source or invented permission guidance")
			}
		}
	}
	corrected := strings.Replace(source, "textContent", "text", 1)
	out := controllerCall(t, d, ctx, id, "mechanize_script_validate", map[string]any{"source": corrected})
	if out.IsError != nil && *out.IsError || controllerBody(t, out)["valid"] != true || dispatches.Load() != 0 {
		t.Fatal("corrected read did not validate without runtime execution")
	}
	// The canonical native endpoint emits the same safe diagnostic.
	native, err := d.server.AsClient(ctx).CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_script_validate", Arguments: map[string]any{"source": source}})
	if err != nil || controllerBody(t, native)["validationCode"] != "unsupportedReadAttribute" {
		t.Fatal("native/compiler boundary lost typed validation diagnostic", err)
	}
}

func TestScriptDiagnosticNeverEchoesUnknownCompilerMessageOrPosition(t *testing.T) {
	diagnostic := closedScriptDiagnostic(&script.Error{Stage: "PRIVATE_STAGE", Position: model.SourceSpan{Line: -1, Column: 1 << 30}, Message: "PRIVATE_LITERAL"})
	out, _ := failure(diagnostic)
	wire, _ := json.Marshal(out)
	if strings.Contains(string(wire), "PRIVATE") || strings.Contains(string(wire), "column") || strings.Contains(string(wire), "line") || controllerBody(t, out)["validationCode"] != "invalidDSL" {
		t.Fatal("unknown compiler detail escaped closed diagnostic")
	}
}
