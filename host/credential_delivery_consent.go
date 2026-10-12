package host

import (
	"context"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

// authorizeCredentialDelivery retains the actual consent lease while the exact
// private exposure capability is held. It does not take an ordinary reader
// permit, clear a durable barrier or authorize public DOM/capture. Only the host
// private delivery composition may call this; no MCP/JSON gate claims are used.
func (h *Host) authorizeCredentialDelivery(ctx context.Context, p auth.Principal, surface model.Surface, binding vault.Binding, protected *vault.DeliveryLease) (*consent.Lease, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return nil, auth.ErrUnauthorized
	}
	if h == nil || h.chrome == nil || h.durable == nil || protected == nil || surface.Kind != "web" || surface.Origin != binding.Target.Origin {
		return nil, vault.ErrUnavailable
	}
	if err := protected.Verify(ctx, binding); err != nil {
		return nil, vault.ErrUnavailable
	}
	lease, err := h.authorizeConsentOperation(ctx, p, surface, true, consent.Control)
	if err != nil {
		return nil, err
	}
	if err = protected.Verify(ctx, binding); err != nil {
		lease.Release()
		return nil, vault.ErrUnavailable
	}
	return lease, nil
}
