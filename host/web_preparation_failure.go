package host

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

func webPreparationCause(err error) string {
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
