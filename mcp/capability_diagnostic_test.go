package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestControllerCapabilityRefusalDoesNotInventPermissionFailure(t *testing.T) {
	d, id, ctx, dispatches := controllerFixture(t, func(deps *Dependencies) {
		deps.Policy = func(context.Context, auth.Principal) (script.Policy, error) {
			return script.Policy{AllowAllWeb: true, AllowMutation: true, Capabilities: map[string]bool{"web:semanticPress": true, "web:replaceValue": true, "web:idLocator": true}}, nil
		}
	})
	session := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
	plan, err := script.Compile(`web.tab(origin:"https://fixture.test").getById("PRIVATE_SELECTOR",exact:true).select("PRIVATE_OPTION")`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Requires = &model.Requirements{Adapters: []string{"web"}}
	source, _ := json.Marshal(plan)
	validated := controllerCall(t, d, ctx, id, "mechanize_script_validate", map[string]any{"source": string(source), "format": "json"})
	if controllerBody(t, validated)["valid"] != true {
		t.Fatal("valid canonical select did not compile")
	}
	out := controllerCall(t, d, ctx, id, "mechanize_step_run", map[string]any{"source": string(source), "format": "json", "sessionId": session, "clientRequestId": "missing-qualified-select", "purpose": "Public fixture"})
	body := controllerBody(t, out)
	if out.IsError == nil || !*out.IsError || body["code"] != "capabilityUnavailable" || body["action"] != "element.select" || body["capability"] != "selectOption" || body["surface"] != "web" || body["dispatchState"] != "notDispatched" || dispatches.Load() != 0 {
		t.Fatal("missing qualified route became a generic permission rejection", body)
	}
	wire, _ := json.Marshal(out)
	if strings.Contains(string(wire), "PRIVATE") || strings.Contains(string(wire), "permissions") {
		t.Fatal("refusal echoed source or invented permission guidance")
	}
}

func TestControllerCapabilityDiagnosticRejectsUnknownAuthorityFields(t *testing.T) {
	for _, body := range []map[string]any{
		{"action": "PRIVATE_ACTION", "surface": "web", "capability": "selectOption", "dispatchState": "notDispatched"},
		{"action": "element.select", "surface": "PRIVATE_SURFACE", "capability": "selectOption", "dispatchState": "notDispatched"},
		{"action": "element.select", "surface": "web", "capability": "PRIVATE_CAPABILITY", "dispatchState": "notDispatched"},
		{"action": "element.select", "surface": "web", "capability": "selectOption", "dispatchState": "unknown"},
	} {
		out := controllerCapabilityRejected(body)
		wire, _ := json.Marshal(out)
		if strings.Contains(string(wire), "PRIVATE") || controllerBody(t, out)["code"] == "capabilityUnavailable" {
			t.Fatal("unqualified provider claim became advertised capability diagnostic")
		}
	}
	for _, code := range []string{"controllerToolRejected", "invalidArguments"} {
		out := controllerRejected("notDispatched", code)
		wire, _ := json.Marshal(out)
		if strings.Contains(string(wire), "permission") {
			t.Fatal("generic rejection suggested more permission")
		}
	}
}
