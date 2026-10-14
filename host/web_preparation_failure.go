package host

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

// Keep the original preparation failure separate from its attempted cleanup.
// The wrapper exposes only a static message; trusted diagnostics map each side
// into closed metadata and never include joined error text.
type webPreparationCleanupFailure struct{ primary, cleanup error }

type webPreparationSubstageFailure struct {
	substage string
	cause    error
}

func (e *webPreparationSubstageFailure) Error() string {
	return "Web provider qualification unavailable"
}
func (e *webPreparationSubstageFailure) Unwrap() error { return e.cause }
func webPreparationAt(substage string, err error) error {
	return &webPreparationSubstageFailure{substage: substage, cause: err}
}
func webPreparationSubstage(err error) string {
	var cleanup *webPreparationCleanupFailure
	if errors.As(err, &cleanup) {
		return webPreparationSubstage(cleanup.primary)
	}
	var primary *webPreparationSubstageFailure
	if errors.As(err, &primary) {
		return primary.substage
	}
	return ""
}

func (e *webPreparationCleanupFailure) Error() string { return "Web preparation cleanup unconfirmed" }
func (e *webPreparationCleanupFailure) Unwrap() []error {
	return []error{e.primary, e.cleanup, ErrWebControlCleanupUnknown}
}
func newWebPreparationCleanupFailure(primary, cleanup error) error {
	return &webPreparationCleanupFailure{primary: primary, cleanup: cleanup}
}
func webPreparationCleanupStatus(err error) string {
	if errors.Is(err, ErrWebControlCleanupUnknown) {
		return "unconfirmed"
	}
	return ""
}
func webPreparationCause(err error) string {
	var failure *webPreparationCleanupFailure
	if errors.As(err, &failure) && failure != nil {
		return webPreparationCause(failure.primary)
	}
	switch {
	case errors.Is(err, ErrWebControlCleanupUnknown):
		return "cleanupUnconfirmed"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, auth.ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, chrome.ErrCredentialPrivacyDocumentChanged):
		return "privacyDocumentChanged"
	case errors.Is(err, vault.ErrDeliveryProtected):
		return "privateProtected"
	case errors.Is(err, ErrWebControlIntent):
		return "intent"
	}
	var detail *model.MechanizeError
	if errors.As(err, &detail) && detail != nil {
		switch detail.Code {
		case "staleAuthority":
			return "leaseChanged"
		case "executorNotQuiescent", "executorBusy":
			return "busy"
		case "capabilityUnavailable":
			return "unsupported"
		}
	}
	return "unavailable"
}
