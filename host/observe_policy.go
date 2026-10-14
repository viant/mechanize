package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/script"
)

// ObservationPolicy checks current enrolled surfaces without discovering
// capabilities or admitting a mutation helper. Host observation still checks
// the exact session/consent and the selected adapter's current authority.
func (h *Host) ObservationPolicy(ctx context.Context, p auth.Principal) (script.Policy, error) {
	if err := ctx.Err(); err != nil {
		return script.Policy{}, err
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || (!actual.HasScope("desktop:observe") && !actual.HasScope("desktop:control")) {
		return script.Policy{}, auth.ErrUnauthorized
	}
	user, err := h.authorize(ctx, p)
	if err != nil {
		return script.Policy{}, err
	}
	allowed := make(map[string]bool, len(user.NativeBundles)+len(user.WebOrigins))
	for _, bundle := range user.NativeBundles {
		allowed[bundle] = true
	}
	for _, origin := range user.WebOrigins {
		allowed[origin] = true
	}
	if err := ctx.Err(); err != nil {
		return script.Policy{}, err
	}
	return script.Policy{AllowedSurfaces: allowed, AllowAllNative: user.DesktopAccess, AllowAllWeb: user.DesktopAccess}, nil
}
