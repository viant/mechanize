package host

import (
	"context"
	"fmt"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
)

// ObserveNativeRoot uses ordinary observation consent for an explicitly selected
// native subtree. It cannot substitute a whole-app observation for that subtree.
func (h *Host) ObserveNativeRoot(ctx context.Context, p auth.Principal, surface model.Surface, root string) (model.Observation, error) {
	user, err := h.authorize(ctx, p)
	if err != nil {
		return model.Observation{}, err
	}
	if surface.Kind != "native" || (root != "menuBar" && root != "focusedElement") {
		return model.Observation{}, fmt.Errorf("supported native observation root required")
	}
	lease, err := h.AuthorizeOperation(ctx, p, surface, false, consent.Observe)
	if err != nil {
		return model.Observation{}, err
	}
	defer lease.Release()
	permitted := user.DesktopAccess
	for _, bundle := range user.NativeBundles {
		if bundle == surface.BundleID {
			permitted = true
		}
	}
	if !permitted {
		return model.Observation{}, auth.ErrUnauthorized
	}
	if gateway := h.nativeFor(p.Namespace); gateway != nil {
		return gateway.ObserveNativeRoot(lease.Context, p, surface, root)
	}
	return model.Observation{}, fmt.Errorf("requested backend is not connected")
}
