package host

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

type credentialPublicReader interface {
	WithVerifiedCredentialPublicRead(context.Context, auth.Principal, model.Surface) (context.Context, error)
}

// A current public-document read does not inherit an old credential input
// lease. The browser verifies the exact current renderer and protects values;
// the retained Vault reader reservation prevents private input during the read.
func (h *Host) authorizeCredentialPublicRead(ctx context.Context, p auth.Principal, surface model.Surface) (*consent.Lease, bool, error) {
	var backend credentialPublicReader
	if h.credentials != nil && h.credentials.browserFixture != nil {
		backend, _ = h.credentials.browserFixture.(credentialPublicReader)
	} else if h.chrome != nil {
		backend = h.chrome
	}
	if backend == nil {
		return nil, false, nil
	}
	lease, err := h.authorizeConsentOperation(ctx, p, surface, false, consent.Observe)
	if err != nil {
		return nil, true, err
	}
	var verified context.Context
	var verificationError error
	verificationStarted := false
	verify := func(c context.Context, _ vault.Binding) error {
		verificationStarted = true
		var e error
		verified, e = backend.WithVerifiedCredentialPublicRead(c, p, surface)
		verificationError = e
		return e
	}
	var release func()
	if h.vaultExposure != nil {
		release, err = h.vaultExposure.AcquireScopedWebExposure(lease.Context, verify)
	} else {
		err = verify(lease.Context, vault.Binding{})
	}
	if err != nil || verified == nil {
		qualificationCanceled := lease.Context.Err() != nil
		lease.Release()
		if release != nil {
			release()
		}
		if verificationError != nil && chrome.CredentialProtectionFailureReason(verificationError) == "scopeUnsupported" {
			return nil, false, nil
		}
		if verificationError == nil && qualificationCanceled {
			return nil, true, credentialPublicReadFailure("scopeUnavailable")
		}
		if errors.Is(verificationError, vault.ErrDeliveryProtected) || errors.Is(verificationError, vault.ErrEntryProtected) || verificationError == nil && (!verificationStarted || verified != nil) && (errors.Is(err, vault.ErrDeliveryProtected) || errors.Is(err, vault.ErrEntryProtected)) {
			return nil, true, vault.ErrDeliveryProtected
		}
		return nil, true, credentialPublicReadFailure(chrome.CredentialProtectionFailureReason(verificationError))
	}
	lease.Context = verified
	if release != nil {
		previous := lease.Release
		lease.Release = func() { defer release(); previous() }
	}
	return lease, true, nil
}

// Only the authenticated verifier's closed classification identifies a private
// target. Missing proof, transport and stale identity never establish privacy.
func credentialPublicReadFailure(reason string) error {
	code, message := "publicReadUnavailable", "Public document read proof is unavailable; inspect current browser connection metadata."
	switch reason {
	case "scopeTargetProtected":
		return vault.ErrDeliveryProtected
	case "scopeChanged":
		code, message = "publicReadIdentityChanged", "Public document identity changed during read qualification; select the current tab and observe again."
	case "scopeInventoryUnavailable":
		code, message = "publicReadInventoryUnavailable", "Current browser tab or frame metadata is unavailable for this read."
	case "scopePreflightBusy":
		code, message = "publicReadBusy", "A current browser exchange prevents this read; wait for its receipt."
	case "scopeLimit":
		code, message = "publicReadLimit", "Public document read proof capacity is exhausted."
	}
	return &model.MechanizeError{Code: code, Message: message, Stage: "admission", DispatchState: "notDispatched", EffectState: "none"}
}
