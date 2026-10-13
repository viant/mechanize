package durable

import (
	"context"
	"errors"
	bootstrapindex "github.com/viant/datly/bootstrap/index"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

var errProtectionMetadataCapacity = errors.New("browser protection projection exceeds bounded capacity")

// ProtectionMetadataFailure is a failed host metadata check, never evidence that
// protections are absent and never a Vault key or credential read failure.
type ProtectionMetadataFailure struct {
	Phase, Cause string
	Err          error
}

func (e *ProtectionMetadataFailure) Error() string { return "browser protection metadata unavailable" }
func (e *ProtectionMetadataFailure) Unwrap() error { return e.Err }
func protectionMetadataFailure(phase string, err error) error {
	cause := "metadataUnavailable"
	switch {
	case errors.Is(err, auth.ErrUnauthorized):
		cause = "authorizationDenied"
	case errors.Is(err, context.Canceled):
		cause = "requestCancelled"
	case errors.Is(err, context.DeadlineExceeded):
		cause = "requestDeadline"
	case errors.Is(err, bootstrapindex.ErrStaleSource):
		cause = "metadataSourceChanged"
	case errors.Is(err, errProtectionMetadataCapacity):
		cause = "projectionCapacityExceeded"
	case errors.Is(err, data.ErrCredentialDeliveryAuthority):
		cause = "projectionShapeInvalid"
	case phase == "bind":
		cause = "metadataSourceUnavailable"
	}
	return &ProtectionMetadataFailure{Phase: phase, Cause: cause, Err: err}
}

// ClosedProtectionMetadataDiagnostic exposes finite enums, not underlying SQL,
// selector values, credentials, document identifiers or internal source paths.
func ClosedProtectionMetadataDiagnostic(err error) (string, string) {
	var d *ProtectionMetadataFailure
	if !errors.As(err, &d) || d == nil {
		return "unknown", "metadataUnavailable"
	}
	switch d.Phase {
	case "identity", "heldContext", "bind", "scopeList", "projection", "legacyList", "legacyProjection", "context":
	default:
		return "unknown", "metadataUnavailable"
	}
	switch d.Cause {
	case "metadataUnavailable", "authorizationDenied", "requestCancelled", "requestDeadline", "metadataSourceChanged", "projectionShapeInvalid", "projectionCapacityExceeded", "metadataSourceUnavailable":
		return d.Phase, d.Cause
	default:
		return d.Phase, "metadataUnavailable"
	}
}
