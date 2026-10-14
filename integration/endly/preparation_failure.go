package endly

import "errors"

// PreparationDiagnostic names only finite local provider stages and causes.
// It contains no target, argument, process identity, content or error text.
type PreparationDiagnostic struct {
	Stage         string `json:"stage"`
	Cause         string `json:"cause"`
	Cleanup       string `json:"cleanup,omitempty"`
	Substage      string `json:"substage,omitempty"`
	Phase         string `json:"phase,omitempty"`
	Reason        string `json:"reason,omitempty"`
	CleanupPhase  string `json:"cleanupPhase,omitempty"`
	CleanupReason string `json:"cleanupReason,omitempty"`
}

func (d PreparationDiagnostic) valid() bool {
	if !validControlDiagnosticPhase(d.Phase) || !validControlDiagnosticPhase(d.CleanupPhase) || !validControlDiagnosticReason(d.Reason) || !validControlDiagnosticReason(d.CleanupReason) || (d.CleanupPhase != "" || d.CleanupReason != "") && d.Cleanup != "unconfirmed" {
		return false
	}

	if d.Substage != "" && d.Substage != "admission" && d.Substage != "readPin" {
		return false
	}
	if d.Cleanup != "" && d.Cleanup != "unconfirmed" {
		return false
	}
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
	return NewStepPreparationFailureWithCleanup(stage, cause, "", err)
}

// NewStepPreparationFailureWithCleanup preserves the original finite failure
// and reports retirement uncertainty independently, before any dispatch.
func NewStepPreparationFailureWithCleanup(stage, cause, cleanup string, err error) error {
	return NewStepPreparationFailureDetail(stage, cause, cleanup, "", err)
}

// NewStepPreparationFailureDetail retains a closed provider substage without
// projecting error text or changing the primary cause/cleanup classification.
func NewStepPreparationFailureDetail(stage, cause, cleanup, substage string, err error, details ...PreparationDiagnostic) error {
	if err == nil {
		return nil
	}
	diagnostic := PreparationDiagnostic{Stage: stage, Cause: cause, Cleanup: cleanup, Substage: substage}
	if len(details) > 1 {
		return err
	}
	if len(details) == 1 {
		diagnostic.Phase = details[0].Phase
		diagnostic.Reason = details[0].Reason
		diagnostic.CleanupPhase = details[0].CleanupPhase
		diagnostic.CleanupReason = details[0].CleanupReason
	}
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

func validControlDiagnosticPhase(value string) bool {
	switch value {
	case "", "acquirePreWrite", "acquireWrite", "acquireAck", "acquireReply", "postAckVerify", "retirePreWrite", "retireWrite", "retireAck", "retireReply", "retireVerify", "retireWait":
		return true
	}
	return false
}
func validControlDiagnosticReason(value string) bool {
	switch value {
	case "credentialLifetime", "credentialActor", "credentialBinding", "credentialSession", "credentialExposure", "credentialLease", "credentialConsent", "credentialExposureChanged", "", "unavailable", "deadline", "cancelled", "unauthorized", "privatePrivacy", "privacyDocumentChanged", "notValidated", "leaseMissing", "leaseMismatch", "identityMismatch", "notQuiesced", "privateDOMUnavailable", "secureDocumentRequired", "staleAuthority", "staleGeneration", "authorityUnconfirmed", "receiptMismatch", "dispatchGateClosed", "dispatchGateExpired", "dispatchGateCancelled", "dispatchGateUnauthorized", "dispatchGateLeaseChanged", "deadlineExceeded", "hostLost", "hostUnavailable", "executorUnknown", "retirementUnknown", "unknownEffect", "mutationBusy", "nativeChannelUnavailable", "processEvidenceUnavailable", "kernelPeerUnqualified", "nativeHostIdentityChanged", "chromeIdentityChanged", "desktopAncestryUnqualified", "channelChanged", "scopeChanged", "processVerificationUnavailable":
		return true
	}
	return false
}
