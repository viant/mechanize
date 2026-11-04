package host

import (
	"context"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
)

func (h *Host) ApplicationPresence(ctx context.Context, p auth.Principal, surface model.Surface) (native.ApplicationPresence, error) {
	user, err := h.authorize(ctx, p)
	if err != nil {
		return native.ApplicationPresence{}, err
	}
	permitted := user.DesktopAccess
	for _, bundle := range user.NativeBundles {
		permitted = permitted || bundle == surface.BundleID
	}
	if !permitted || surface.Kind != "native" || surface.BundleID == "" || surface.ProcessID != 0 || surface.ProcessStartToken != "" || surface.Origin != "" || surface.Title != "" || surface.TabID != "" {
		return native.ApplicationPresence{}, auth.ErrUnauthorized
	}
	lease, err := h.AuthorizeOperation(ctx, p, surface, false, consent.Observe)
	if err != nil {
		return native.ApplicationPresence{}, err
	}
	defer lease.Release()
	if gateway := h.nativeFor(p.Namespace); gateway != nil {
		return gateway.ApplicationPresence(lease.Context, p, surface)
	}
	return native.ApplicationPresence{}, ErrNativeControlUnqualified
}
