package host

import (
	"context"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

// Catalogue authorization grants no platform execution authority. Exact surface
// ceilings apply even when an otherwise unqualified draft is merely stored.
func (h *Host) AuthorizeScenarioSurface(ctx context.Context, requested auth.Principal, surface model.Surface) error {
	actual, err := auth.FromContext(ctx)
	if err != nil || requested.Validate() != nil || requested.Namespace != actual.Namespace || requested.ClientID != actual.ClientID {
		return auth.ErrUnauthorized
	}
	user, err := h.authorize(ctx, actual)
	if err != nil {
		return err
	}
	if surface == (model.Surface{}) {
		return nil
	}
	switch surface.Kind {
	case "native":
		if surface.BundleID == "" || surface.Origin != "" || surface.TabID != "" {
			return auth.ErrUnauthorized
		}
		if user.DesktopAccess {
			return nil
		}
		for _, bundle := range user.NativeBundles {
			if bundle == surface.BundleID {
				return nil
			}
		}
	case "web":
		if surface.Origin == "" || surface.BundleID != "" {
			return auth.ErrUnauthorized
		}
		if user.DesktopAccess {
			return nil
		}
		for _, origin := range user.WebOrigins {
			if origin == surface.Origin {
				return nil
			}
		}
	}
	return auth.ErrUnauthorized
}
