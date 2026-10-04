package host

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
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
	if h.consent == nil {
		return nil, errors.New("native permission broker is unavailable")
	}
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || binding.Purpose == "" {
		return nil, &model.MechanizeError{Code: "permissionRequired", Message: "Request native consent for this client, session and exact target before dispatch", Stage: "consent", DispatchState: "notDispatched"}
	}
	scope, err := ConsentScope(surface)
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
		grant, err := h.consent.FindPermanentGrant(ctx, p, operation)
		if err != nil {
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
		return gate.retain(generation, lease)
	}
	return lease, nil
}
