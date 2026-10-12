package host

import (
	"context"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
)

type tabHandleReader interface {
	ListTabHandles(context.Context, auth.Principal, string) (chrome.TabHandleInventory, error)
}

func (h *Host) BrowserTabs(ctx context.Context, p auth.Principal, surface model.Surface) (chrome.TabHandleInventory, error) {
	var reader tabHandleReader
	if h.chrome != nil {
		reader = h.chrome
	}
	return h.browserTabs(ctx, p, surface, reader)
}
func (h *Host) browserTabs(ctx context.Context, p auth.Principal, surface model.Surface, reader tabHandleReader) (chrome.TabHandleInventory, error) {
	out := chrome.TabHandleInventory{Tabs: []chrome.TabHandle{}}
	if surface.Kind != "web" || !chrome.OrdinaryWebsiteOrigin(surface.Origin) || surface.TabID != "" || surface.Title != "" || surface.BundleID != "" || surface.ProcessID != 0 || surface.ProcessStartToken != "" {
		return out, auth.ErrUnauthorized
	}
	if _, err := h.authorize(ctx, p); err != nil {
		return out, err
	}
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || h.Runtime == nil || h.Runtime.CheckSession(ctx, p, binding.SessionID) != nil {
		return out, auth.ErrUnauthorized
	}
	// Exact-origin handles contain no titles, DOM or values and confer no input
	// authority. Use the same consent-only metadata seam as location comparison.
	lease, err := h.authorizeConsentOperation(ctx, p, surface, false, consent.Observe)
	if err != nil {
		return out, err
	}
	defer lease.Release()
	if reader == nil {
		return out, auth.ErrUnauthorized
	}
	inventory, err := reader.ListTabHandles(lease.Context, p, surface.Origin)
	if err != nil {
		return out, err
	}
	return inventory, lease.Context.Err()
}
