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
	if !known || missing.Surface != "web" && missing.Surface != "native" {
		return nil
	}
	if missing.Locator == "" {
		if action.Capability != missing.Capability || len(missing.Alternatives) != 0 {
			return nil
		}
	} else {
		if script.LocatorCapability(missing.Locator) == "" || script.LocatorCapability(missing.Locator) != missing.Capability || len(missing.Alternatives) > 6 {
			return nil
		}
		seen := map[string]bool{}
		for _, alternative := range missing.Alternatives {
			if script.LocatorCapability(alternative) == "" || alternative == missing.Locator || seen[alternative] {
				return nil
			}
			seen[alternative] = true
		}
	}
	body := map[string]any{"code": "capabilityUnavailable", "message": "The requested action is unavailable in the current qualified capabilities. Use mechanize_capabilities and mechanize_describe to select an advertised operation.", "stage": "validation", "dispatchState": "notDispatched", "action": action.Action, "surface": missing.Surface, "capability": missing.Capability}
	if missing.Locator != "" {
		body["message"] = "The requested locator is unavailable for this action. Use an advertised locator alternative and validate the same source."
		body["locator"] = missing.Locator
		body["alternatives"] = append([]string{}, missing.Alternatives...)
	}
	return body
}

func controllerCapabilityRejected(body map[string]any) *schema.CallToolResult {
	action, _ := body["action"].(string)
	surface, _ := body["surface"].(string)
	capability, _ := body["capability"].(string)
	missing := &script.CapabilityUnavailableError{Action: action, Surface: surface, Capability: capability}
	if locator, ok := body["locator"].(string); ok {
		missing.Locator = locator
	}
	if values, present := body["alternatives"]; present {
		array, ok := values.([]any)
		if !ok {
			return controllerRejected("unknown")
		}
		for _, value := range array {
			text, ok := value.(string)
			if !ok {
				return controllerRejected("unknown")
			}
			missing.Alternatives = append(missing.Alternatives, text)
		}
	}
	diagnostic := closedCapabilityDiagnostic(missing)
	if body["dispatchState"] != "notDispatched" || diagnostic == nil {
		return controllerRejected("unknown")
	}
	out, _ := result(diagnostic)
	yes := true
	out.IsError = &yes
	return out
}
