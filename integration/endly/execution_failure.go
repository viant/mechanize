package endly

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

// ExecutionFailure is copied from a typed executor failure before Endly turns
// errors into text. It is live operational metadata, not business verification,
// a reconstructed receipt, or permission to retry an input.
type ExecutionFailure struct {
	Preparation   *PreparationDiagnostic `json:"preparation,omitempty"`
	Playwright    *PlaywrightDiagnostic  `json:"playwright,omitempty"`
	Code          string                 `json:"code"`
	DispatchState string                 `json:"dispatchState"`
}

// Native adapters implement this only for correlated, qualified helper replies.
// Keeping the interface here avoids coupling Endly to a platform backend.
type nativeExecutionFailure interface{ NativeExecutionFailure() (string, string, bool) }

func executionFailure(result StepResult, err error) *ExecutionFailure {
	if err == nil {
		return nil
	}
	var prepared *stepPreparationFailure
	if errors.As(err, &prepared) && prepared != nil && prepared.diagnostic.valid() && result.DispatchState == "notDispatched" && result.ExecutionFailure != nil && result.ExecutionFailure.Valid() && result.ExecutionFailure.Code == "webPreparationUnavailable" && *result.ExecutionFailure.Preparation == prepared.diagnostic {
		diagnostic := prepared.diagnostic
		return &ExecutionFailure{Code: "webPreparationUnavailable", DispatchState: "notDispatched", Preparation: &diagnostic}
	}
	code, reported := "", ""
	var typed *model.MechanizeError
	if errors.As(err, &typed) && typed != nil && executionFailureCode(typed.Code) && !model.NativeExecutionFailureCode(typed.Code) {
		if (typed.Code == "permissionRequired" || typed.Code == "permissionExpired" || typed.Code == "permissionDenied") && (typed.Stage != "consent" || typed.DispatchState != "notDispatched" || typed.EffectState != "" && typed.EffectState != "none") {
			return nil
		}
		if typed.Code == "bindingUnconfirmed" && (typed.Stage != "browser" || typed.DispatchState != "notDispatched" || typed.EffectState != "none") {
			return nil
		}
		// Frame expiry is a local pre-I/O rejection, not a generic helper error.
		if typed.Code == "staleFramePermit" && (typed.Stage != "native" || typed.DispatchState != "notDispatched" || typed.EffectState != "none") {
			return nil
		}
		code, reported = typed.Code, typed.DispatchState
	} else {
		var native nativeExecutionFailure
		if !errors.As(err, &native) {
			return nil
		}
		var qualified bool
		code, reported, qualified = native.NativeExecutionFailure()
		if !qualified || !model.NativeExecutionFailureCode(code) {
			return nil
		}
	}
	state := result.DispatchState
	if state == "" {
		state = reported
	}
	if !executionDispatchState(state) || reported != "" && reported != state {
		state = "unknown"
	}
	captured := &ExecutionFailure{Code: code, DispatchState: state}
	var diagnostic playwrightDiagnosticFailure
	if errors.As(err, &diagnostic) {
		value := diagnostic.PlaywrightExecutionDiagnostic()
		if value.valid(code) {
			captured.Playwright = &value
		}
	}
	return captured
}

// Valid is also used at the controller projection boundary; unknown provider
// strings cannot become a public diagnostic through a loosely typed response.
func (f ExecutionFailure) Valid() bool {
	if f.Code == "webPreparationUnavailable" {
		return f.DispatchState == "notDispatched" && f.Preparation != nil && f.Preparation.valid() && f.Playwright == nil
	}
	if f.Preparation != nil {
		return false
	}
	return executionFailureCode(f.Code) && executionDispatchState(f.DispatchState) && (f.Playwright == nil || f.Playwright.valid(f.Code))
}
func executionDispatchState(s string) bool {
	return s == "notDispatched" || s == "dispatched" || s == "unknown"
}
func executionFailureCode(code string) bool {
	if model.NativeExecutionFailureCode(code) {
		return true
	}
	switch code {
	case "permissionRequired", "permissionExpired", "permissionDenied", "bindingUnconfirmed":
		return true
	case "protectionMetadataUnavailable", "staleFramePermit", "privateDOMUnavailable", "publicReadIdentityChanged", "publicReadInventoryUnavailable", "publicReadBusy", "publicReadLimit", "publicReadUnavailable", "invalidPredicate", "playwrightRuntimeQualification", "playwrightChildLaunch", "playwrightDeadline", "playwrightIPCFrame", "playwrightIPCProtocol", "playwrightIPCWrite", "playwrightChildExited", "playwrightAttemptCapacity", "playwrightAttemptConflict", "playwrightAuthorityChanged", "playwrightAuthorityDenied", "playwrightBindingRequired", "playwrightBusy", "playwrightCommandDenied", "playwrightDocumentChanged", "playwrightFingerprintMismatch", "playwrightHostRequired", "playwrightIntentRequired", "playwrightLocatorDenied", "playwrightOriginDenied", "playwrightPrivateDOMDenied", "playwrightReadDenied", "playwrightReadTooLarge", "playwrightReceiptUncertain", "playwrightRedactionDenied", "playwrightTargetDenied", "playwrightTargetUnpinned", "playwrightTargetChanged", "playwrightUnavailable", "playwrightUncertain", "playwrightExecutionRequired", "playwrightHostDeadline", "playwrightHostDenied", "playwrightHostDisconnected", "playwrightRelayDenied":
		return true
	}
	return false
}

// ExecutionFailure returns a detached snapshot only for the same client's live
// session and operation. Older operations without capture return nil; their
// flattened error text and missing unresolved effects are never interpreted.
func (r *Runtime) ExecutionFailure(ctx context.Context, session, operation string) (*ExecutionFailure, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	actor, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	owner, ok := r.principals[session]
	if !ok || r.closingSessions[session] || owner.Namespace != actor.Namespace || owner.ClientID != actor.ClientID {
		return nil, auth.ErrUnauthorized
	}
	for _, p := range r.programs {
		if p.owner == session && p.operationID == operation {
			if p.executionFailure == nil {
				return nil, nil
			}
			copied := *p.executionFailure
			if copied.Preparation != nil {
				value := *copied.Preparation
				copied.Preparation = &value
			}
			if copied.Playwright != nil {
				value := *copied.Playwright
				copied.Playwright = &value
			}
			return &copied, nil
		}
	}
	return nil, errors.New("owned execution failure metadata unavailable")
}

// CaptureExecutionFailure preserves only the same closed typed executor evidence
// for durable outcome publication. Serialized metadata alone cannot confer input.
func CaptureExecutionFailure(result StepResult, err error) *ExecutionFailure {
	return executionFailure(result, err)
}
