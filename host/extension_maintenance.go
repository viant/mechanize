package host

import (
	"context"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	gateway "github.com/viant/mechanize/mcp"
)

func (h *Host) extensionMaintenanceActor(ctx context.Context, requested auth.Principal, in gateway.ExtensionMaintenanceInput) (auth.Principal, error) {
	p, e := auth.FromContext(ctx)
	if e != nil || requested.Validate() != nil || p.Namespace != requested.Namespace || p.ClientID == "" || p.ClientID != requested.ClientID || strings.HasPrefix(p.ClientID, "controller:") || !p.HasScope("desktop:control") || h.Runtime == nil || h.Runtime.CheckSession(ctx, p, in.SessionID) != nil || in.ClientRequestID == "" || len(in.ClientRequestID) > 128 || !chrome.ValidExtensionVersion(in.ExpectedVersion) {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	if _, e = h.authorize(ctx, p); e != nil {
		return auth.Principal{}, e
	}
	return p, nil
}

// ExtensionReload is local connector maintenance, not native UI input.
// Existing ownership/control authorization and secure-entry exclusion apply;
// Accessibility, Screen Recording and app focus are not prerequisites.
func (h *Host) ExtensionReload(ctx context.Context, requested auth.Principal, in gateway.ExtensionMaintenanceInput) (chrome.ExtensionMaintenanceResult, error) {
	p, e := h.extensionMaintenanceActor(ctx, requested, in)
	if e != nil {
		return chrome.ExtensionMaintenanceResult{}, e
	}
	if h.chrome == nil {
		return chrome.ExtensionMaintenanceResult{Outcome: "notDispatched", DispatchState: "notDispatched", Reason: "channelUnavailable"}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if h.vaultExposure != nil {
		release, err := h.vaultExposure.AcquireNativeExposureContext(ctx)
		if err != nil {
			return chrome.ExtensionMaintenanceResult{}, err
		}
		defer release()
	}
	admit := func(check context.Context) error {
		_, err := h.extensionMaintenanceActor(check, requested, in)
		return err
	}
	return h.chrome.ReloadExtension(ctx, p, in.SessionID, in.ClientRequestID, in.ProfileChannel, in.BrowserInstance, in.ExpectedVersion, admit)
}

// ExtensionReloadStatus observes the original intent; it never sends reload.
// Session close/revocation or foreign ownership cannot be replaced with a new
// identity to inspect or revive an old maintenance operation.
func (h *Host) ExtensionReloadStatus(ctx context.Context, requested auth.Principal, in gateway.ExtensionMaintenanceInput) (chrome.ExtensionMaintenanceResult, error) {
	p, e := h.extensionMaintenanceActor(ctx, requested, in)
	if e != nil {
		return chrome.ExtensionMaintenanceResult{}, e
	}
	if h.chrome == nil {
		return chrome.ExtensionMaintenanceResult{Outcome: "unknown", DispatchState: "unknown", Reason: "channelUnavailable"}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	return h.chrome.ExtensionReloadStatus(ctx, p, in.SessionID, in.ClientRequestID, in.ProfileChannel, in.BrowserInstance, in.ExpectedVersion)
}
