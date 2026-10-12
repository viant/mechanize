package host

import (
	"context"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
)

func (h *Host) BrowserStatus(ctx context.Context, requested auth.Principal) (chrome.BrowserStatus, error) {
	p, err := auth.FromContext(ctx)
	if err != nil || requested.Validate() != nil || p.Namespace != requested.Namespace || p.ClientID != requested.ClientID {
		return chrome.BrowserStatus{}, auth.ErrUnauthorized
	}
	if _, err = h.authorize(ctx, p); err != nil {
		return chrome.BrowserStatus{}, err
	}
	if h.chrome == nil {
		status := chrome.BrowserStatus{Available: false, Channels: []chrome.BrowserChannelStatus{}}
		if h.chromeStartupUnqualified {
			status.AttentionCode = "chromeProcessUnqualified"
		}
		setup := status.SetupStatus()
		status.Setup = &setup
		return status, ctx.Err()
	}
	status, err := h.chrome.BrowserStatus(ctx, p)
	if err != nil {
		return chrome.BrowserStatus{}, err
	}
	setup := status.SetupStatus()
	status.Setup = &setup
	return status, nil
}
