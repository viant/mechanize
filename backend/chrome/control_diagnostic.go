package chrome

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type controlFailure struct {
	phase, reason string
	cause         error
}

func (e *controlFailure) Error() string { return "renderer control metadata unavailable" }
func (e *controlFailure) Unwrap() error { return e.cause }
func controlFailureAt(phase string, err error, reason ...string) error {
	if err == nil {
		return nil
	}
	code := controlFailureReason(err)
	if len(reason) == 1 {
		code = reason[0]
	}
	return &controlFailure{phase: phase, reason: code, cause: err}
}

// ControlFailureDiagnostic projects only closed metadata phases/reasons. It does
// not assert input delivery, establish retirement, or expose an error message.
func ControlFailureDiagnostic(err error) (string, string) {
	var detail *controlFailure
	if !errors.As(err, &detail) || detail == nil {
		return "", ""
	}
	switch detail.phase {
	case "acquirePreWrite", "acquireWrite", "acquireAck", "acquireReply", "postAckVerify", "retirePreWrite", "retireWrite", "retireAck", "retireReply", "retireVerify":
	default:
		return "", ""
	}
	switch detail.reason {
	case "credentialLifetime", "credentialActor", "credentialBinding", "credentialSession", "credentialExposure", "credentialLease", "credentialConsent", "credentialExposureChanged", "unavailable", "deadline", "cancelled", "unauthorized", "privatePrivacy", "privacyDocumentChanged", "notValidated", "leaseMissing", "leaseMismatch", "identityMismatch", "notQuiesced", "privateDOMUnavailable", "secureDocumentRequired", "staleAuthority", "staleGeneration", "authorityUnconfirmed", "receiptMismatch", "dispatchGateClosed", "dispatchGateExpired", "dispatchGateCancelled", "dispatchGateUnauthorized", "dispatchGateLeaseChanged", "deadlineExceeded", "hostLost", "hostUnavailable", "executorUnknown", "retirementUnknown", "unknownEffect", "mutationBusy", "nativeChannelUnavailable", "processEvidenceUnavailable", "kernelPeerUnqualified", "nativeHostIdentityChanged", "chromeIdentityChanged", "desktopAncestryUnqualified", "channelChanged", "scopeChanged", "processVerificationUnavailable":
		return detail.phase, detail.reason
	}
	return detail.phase, "unavailable"
}
func controlFailureReason(err error) string {
	var callback interface{ CredentialAdmissionReason() string }
	if errors.As(err, &callback) {
		return callback.CredentialAdmissionReason()
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, auth.ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrCredentialPrivacyDocumentChanged):
		return "privacyDocumentChanged"
	case errors.Is(err, errCredentialPrivacy):
		return "privatePrivacy"
	}
	var process *channelProcessDiagnostic
	if errors.As(err, &process) {
		return processVerificationReason(err)
	}
	var detail *model.MechanizeError
	if errors.As(err, &detail) {
		if detail.Code == "deadlineExceeded" {
			return "deadline"
		}
		return detail.Code
	}
	return "unavailable"
}
