package host

import (
	"context"
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
	verify := func(c context.Context, _ vault.Binding) error {
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
		lease.Release()
		if release != nil {
			release()
		}
		if verificationError != nil && chrome.CredentialProtectionFailureReason(verificationError) == "scopeUnsupported" {
			return nil, false, nil
		}
		return nil, true, vault.ErrDeliveryProtected
	}
	lease.Context = verified
	if release != nil {
		previous := lease.Release
		lease.Release = func() { defer release(); previous() }
	}
	return lease, true, nil
}
