package host

import (
	"context"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

func (h *Host) enrolled(ctx context.Context, p auth.Principal) (User, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace {
		return User{}, auth.ErrUnauthorized
	}
	u, ok := h.users[p.Namespace]
	if !ok {
		return User{}, auth.ErrUnauthorized
	}
	return u, nil
}
func (h *Host) ConsentPolicy(ctx context.Context, p auth.Principal, scope consent.Scope, modes []consent.Mode, duration int) error {
	user, err := h.enrolled(ctx, p)
	if err != nil {
		return err
	}
	if err = scope.Validate(); err != nil {
		return err
	}
	if duration < 1 || duration > 900 {
		return errors.New("consent exceeds host duration ceiling")
	}
	allowed := false
	switch scope.Kind {
	case "browser":
		allowed = user.DesktopAccess && h.chromeAllWebsites[p.Namespace]
	case "desktop":
		allowed = user.DesktopAccess
	case "application":
		allowed = user.DesktopAccess
		for _, bundle := range user.NativeBundles {
			if bundle == scope.BundleID {
				allowed = true
			}
		}
	case "origin":
		allowed = user.DesktopAccess
		for _, origin := range user.WebOrigins {
			if origin == scope.Origin {
				allowed = true
			}
		}
	case "window":
		return errors.New("stable native window grant mapping is not qualified")
	}
	if !allowed {
		return auth.ErrUnauthorized
	}
	for _, mode := range modes {
		switch mode {
		case consent.Observe:
			if !p.HasScope("desktop:observe") && !p.HasScope("desktop:control") {
				return auth.ErrUnauthorized
			}
		case consent.Control:
			if !p.HasScope("desktop:control") {
				return auth.ErrUnauthorized
			}
		case consent.Record:
			if !p.HasScope("desktop:control") || !user.RecordingAllowed {
				return auth.ErrUnauthorized
			}
		default:
			return auth.ErrUnauthorized
		}
	}
	return nil
}
func (h *Host) AuthorizeOperation(ctx context.Context, p auth.Principal, surface model.Surface, mutation bool, requested consent.Mode) (*consent.Lease, error) {
	if h.chromeStartupUnqualified && surface.Kind == "web" {
		return nil, chrome.ErrProcessQualification
	}
	// Browser delivery protects its exact DOM/value scope; it is not a global
	// native desktop prohibition. Existing native value-read restrictions and
	// secure Vault entry exclusion remain independent of effect uncertainty.
	if surface.Kind == "native" {
		if _, err := h.enrolled(ctx, p); err != nil {
			return nil, err
		}
	}
	// Durable browser protection survives restart. Its generated scoped reader
	// honors an existing held user lock; no browser lane is acquired here.
	if h.durable != nil {
		if surface.Kind == "web" {
			scopes, err := h.durable.CredentialProtectionScopes(ctx, p, surface.Origin)
			if err != nil {
				return nil, protectionMetadataAdmissionFailure(err)
			}
			if len(scopes) > 0 {
				if !mutation && requested == consent.Observe {
					if lease, handled, e := h.authorizeCredentialPublicRead(ctx, p, surface); handled {
						return lease, e
					}
				}
				if h.credentials != nil {
					if lease, e := h.credentials.authorizeDOM(ctx, p, surface, mutation, requested); e == nil {
						return lease, nil
					} else {
						var reason *model.MechanizeError
						if errors.As(e, &reason) && reason.Code == "credentialPurposeMismatch" && reason.Stage == "consent" && reason.DispatchState == "notDispatched" && reason.EffectState == "none" {
							return nil, e
						}
					}
				}
				return h.authorizeDisjointWeb(ctx, p, surface, mutation, requested, scopes)
			}
		} else if surface.Kind != "native" {
			blocked, err := h.durable.CredentialDeliveryBlocked(ctx, p)
			if err != nil {
				return nil, vault.ErrUnavailable
			}
			if blocked {
				return nil, vault.ErrDeliveryProtected
			}
		}
	}

	// Exact selected public reads can use their existing read-only renderer
	// proof while unrelated old executors remain unqualified or uncertain.
	if surface.Kind == "web" && !mutation && requested == consent.Observe && h.chrome != nil && h.chrome.NeedsVerifiedPublicRead(ctx, p, surface) {
		if lease, handled, err := h.authorizeCredentialPublicRead(ctx, p, surface); handled {
			return lease, err
		}
	}

	// The permit covers the entire consent lease, including recording lifetimes
	// and retained capture/control permits. Entry cannot begin until they release.
	var releaseExposure func()
	if h.vaultExposure != nil {
		var err error
		if surface.Kind == "native" {
			releaseExposure, err = h.vaultExposure.AcquireNativeExposureContext(ctx)
		} else {
			releaseExposure, err = h.vaultExposure.AcquireExposureContext(ctx)
		}
		if err != nil {
			return nil, err
		}
	}
	retained := false
	defer func() {
		if !retained && releaseExposure != nil {
			releaseExposure()
		}
	}()
	lease, err := h.authorizeConsentOperation(ctx, p, surface, mutation, requested)
	if err != nil {
		return nil, err
	}
	if releaseExposure != nil {
		previous := lease.Release
		lease.Release = func() { defer releaseExposure(); previous() }
		retained = true
	}
	return lease, nil
}

// authorizeConsentOperation shares actual policy, session and durable consent
// checks. Callers supply either ordinary exposure or an exact private delivery
// lease; this helper alone is never an exposed authorization API.
func (h *Host) authorizeConsentOperation(ctx context.Context, p auth.Principal, surface model.Surface, mutation bool, requested consent.Mode) (*consent.Lease, error) {
	if err := h.checkCredentialCleanupOperation(ctx, p, surface, mutation, requested); err != nil {
		return nil, err
	}
	if h.consent == nil {
		return nil, errors.New("native permission broker is unavailable")
	}
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || binding.Purpose == "" {
		return nil, &model.MechanizeError{Code: "permissionRequired", Message: "Request native consent for this client, session and exact target before dispatch", Stage: "consent", DispatchState: "notDispatched"}
	}
	scope, err := h.operationConsentScope(p, surface)
	if err != nil {
		return nil, err
	}
	mode := consent.Observe
	if mutation {
		mode = requested
	}
	var gate *applicationPolicyGate
	var generation uint64
	if h.applicationAccess != nil {
		gate, generation, err = h.applicationAccess.admission(ctx, p, scope, mode)
		if err != nil {
			return nil, err
		}
	}
	operation := consent.Operation{GrantID: binding.GrantID, SessionID: binding.SessionID, Scope: scope, Mode: mode, Purpose: binding.Purpose}
	if binding.GrantID == "" {
		grant, err := h.consent.ResolveControllerPolicyGrant(ctx, p, operation)
		if err == nil && grant == nil {
			grant, err = h.consent.FindPermanentGrant(ctx, p, operation)
		}
		if err != nil {
			if errors.Is(err, consent.ErrCleanupUnconfirmed) {
				return nil, &model.MechanizeError{Code: "consentCleanupUnconfirmed", Stage: "cleanup", DispatchState: "notDispatched", Message: "Existing approval is retained but executor cleanup is unconfirmed. Recover the previous automation before continuing."}
			}
			return nil, err
		}
		if grant == nil {
			return nil, &model.MechanizeError{Code: "permissionRequired", Message: "Approve this session or trust this verified tool until revoked", Stage: "consent", DispatchState: "notDispatched"}
		}
		binding.GrantID = grant.ID
		operation.GrantID = grant.ID
		ctx = auth.WithConsentBinding(ctx, binding)
	}
	lease, err := h.consent.Authorize(ctx, p, operation)
	if err != nil {
		return nil, err
	}
	if gate != nil {
		lease, err = gate.retain(generation, lease)
		if err != nil {
			return nil, err
		}
	}
	return lease, nil
}

// Metadata unavailability remains a pre-input denial. The closed diagnostic
// cannot weaken a retained protection or expose the underlying reader error.
type protectionAdmissionFailure struct {
	detail *model.MechanizeError
	cause  error
}

func (e *protectionAdmissionFailure) Error() string   { return e.detail.Error() }
func (e *protectionAdmissionFailure) Unwrap() []error { return []error{e.detail, e.cause} }
func protectionMetadataAdmissionFailure(err error) error {
	phase, cause := durable.ClosedProtectionMetadataDiagnostic(err)
	return &protectionAdmissionFailure{detail: &model.MechanizeError{Code: "protectionMetadataUnavailable", Message: fmt.Sprintf("Browser protection metadata is unavailable (%s/%s).", phase, cause), Stage: "admission", DispatchState: "notDispatched", EffectState: "none"}, cause: err}
}
