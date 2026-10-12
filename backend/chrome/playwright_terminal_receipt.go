package chrome

import (
	"encoding/json"
	"reflect"
)

// This is a receipt from the authenticated active worker, after journal readback.
// No page data or sidecar-supplied dispatch classification is accepted here.
func playwrightTerminalReceipt(raw json.RawMessage, command Command, inputPossible bool) *Reply {
	var result struct {
		Receipt struct {
			RequestID          string   `json:"requestId"`
			AttemptID          string   `json:"attemptId"`
			Identity           Identity `json:"identity"`
			ControlLease       *Lease   `json:"controlLease"`
			FingerprintVersion int      `json:"fingerprintVersion"`
			FingerprintSHA256  string   `json:"fingerprintSHA256"`
			DispatchState      string   `json:"dispatchState"`
			EffectState        string   `json:"effectState"`
			InputSemantics     string   `json:"inputSemantics,omitempty"`
			Error              *struct {
				Code          string `json:"code"`
				Message       string `json:"message"`
				Stage         string `json:"stage"`
				DispatchState string `json:"dispatchState"`
				EffectState   string `json:"effectState"`
			} `json:"error,omitempty"`
		} `json:"receipt"`
	}
	if closedPlaywright(raw, &result) != nil {
		return nil
	}
	r := result.Receipt
	if command.AttemptID == "" || r.RequestID != command.RequestID || r.AttemptID != command.AttemptID || r.Identity != command.Identity || !reflect.DeepEqual(r.ControlLease, command.ControlLease) || r.FingerprintVersion != 2 || r.FingerprintSHA256 != command.FingerprintSHA256 || r.InputSemantics != "" && r.InputSemantics != "Local Playwright over scoped extension CDP" {
		return nil
	}
	switch r.DispatchState {
	case "notDispatched":
		if inputPossible || r.EffectState != "none" {
			return nil
		}
	case "unknown":
		if r.EffectState != "unknown" {
			return nil
		}
	case "dispatched":
		if !inputPossible || r.EffectState != "unverified" {
			return nil
		}
	default:
		return nil
	}
	code := ""
	if r.Error != nil {
		if r.Error.Stage != "browser" || r.Error.DispatchState != r.DispatchState || r.Error.EffectState != map[bool]string{true: "unknown", false: "none"}[r.DispatchState == "unknown"] {
			return nil
		}
		code = safePlaywrightError(r.Error.Code)
	}
	reply := playwrightReply(command, r.DispatchState, r.EffectState, code, nil)
	return &reply
}
