package mcp

import (
	"errors"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func closedCapabilityDiagnostic(err error) map[string]any {
	var missing *script.CapabilityUnavailableError
	if !errors.As(err, &missing) || missing == nil {
		return nil
	}
	action, known := model.ActionByName(missing.Action)
	if !known || action.Capability != missing.Capability || missing.Surface != "web" && missing.Surface != "native" {
		return nil
	}
	return map[string]any{"code": "capabilityUnavailable", "message": "The requested action is unavailable in the current qualified capabilities. Use mechanize_capabilities and mechanize_describe to select an advertised operation.", "stage": "validation", "dispatchState": "notDispatched", "action": action.Action, "surface": missing.Surface, "capability": missing.Capability}
}

func controllerCapabilityRejected(body map[string]any) *schema.CallToolResult {
	action, _ := body["action"].(string)
	surface, _ := body["surface"].(string)
	capability, _ := body["capability"].(string)
	diagnostic := closedCapabilityDiagnostic(&script.CapabilityUnavailableError{Action: action, Surface: surface, Capability: capability})
	if body["dispatchState"] != "notDispatched" || diagnostic == nil {
		return controllerRejected("unknown")
	}
	out, _ := result(diagnostic)
	yes := true
	out.IsError = &yes
	return out
}
