package endly

import "errors"

// PreparationDiagnostic names only finite local provider stages and causes.
// It contains no target, argument, process identity, content or error text.
type PreparationDiagnostic struct {
	Stage string `json:"stage"`
	Cause string `json:"cause"`
}

func (d PreparationDiagnostic) valid() bool {
	switch d.Stage {
	case "executor", "actor", "validation", "intent", "qualify", "newLease", "capability", "readPin", "publish":
	default:
		return false
	}
	switch d.Cause {
	case "unavailable", "unauthorized", "cancelled", "deadline", "unsupported", "intent", "privacyDocumentChanged", "privateProtected", "cleanupUnconfirmed", "leaseChanged", "busy":
		return true
	}
	return false
}

type stepPreparationFailure struct {
	cause      error
	diagnostic PreparationDiagnostic
}

func (e *stepPreparationFailure) Error() string { return "Web executor preparation unavailable" }
func (e *stepPreparationFailure) Unwrap() error { return e.cause }

// NewStepPreparationFailure reports a trusted provider's finite local phase.
// It does not establish whether input was dispatched. Only the durable pre-intent edge may
// publish this as a notDispatched ExecutionFailure.
func NewStepPreparationFailure(stage, cause string, err error) error {
	if err == nil {
		return nil
	}
	diagnostic := PreparationDiagnostic{Stage: stage, Cause: cause}
	if !diagnostic.valid() {
		return err
	}
	return &stepPreparationFailure{cause: err, diagnostic: diagnostic}
}

// CaptureStepPreparationFailure is used only where executor preparation has
// returned before BeginAttempt/dispatch. Existing runtime ownership binds it to
// the original operation; neither text nor absent receipts reconstruct it.
func CaptureStepPreparationFailure(err error) *ExecutionFailure {
	var proof *stepPreparationFailure
	if !errors.As(err, &proof) || proof == nil || !proof.diagnostic.valid() {
		return nil
	}
	diagnostic := proof.diagnostic
	return &ExecutionFailure{Code: "webPreparationUnavailable", DispatchState: "notDispatched", Preparation: &diagnostic}
}
