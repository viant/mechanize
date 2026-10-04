package host

import (
	"context"
	"fmt"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
)

// ObserveNativeWindow uses the existing observation grant and value-withholding
// gateway. It narrows one exact process to one unique title; no broad fallback.
func (h *Host) ObserveNativeWindow(ctx context.Context, p auth.Principal, surface model.Surface, title, role string) (model.Observation, error) {
	user, err := h.authorize(ctx, p)
	if err != nil {
		return model.Observation{}, err
	}
	if err = native.ValidateNativeWindowRequest(surface, title, role); err != nil {
		return model.Observation{}, err
	}
	permitted := user.DesktopAccess
	for _, bundle := range user.NativeBundles {
		permitted = permitted || bundle == surface.BundleID
	}
	if !permitted {
		return model.Observation{}, auth.ErrUnauthorized
	}
	lease, err := h.AuthorizeOperation(ctx, p, surface, false, consent.Observe)
	if err != nil {
		return model.Observation{}, err
	}
	defer lease.Release()
	if gateway := h.nativeFor(p.Namespace); gateway != nil {
		return gateway.ObserveNativeWindow(lease.Context, p, surface, title, role)
	}
	return model.Observation{}, fmt.Errorf("requested backend is not connected")
}
