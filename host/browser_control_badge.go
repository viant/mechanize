package host

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/session"
)

// Presentation is tied to an admitted browser operation, never a model-supplied
// target. The helper independently resolves the exact native window. Failure to
// draw is not authority to retry the browser action or activate a window.
func (h *Host) presentBrowserControlBadge(ctx context.Context, p auth.Principal, process session.ProcessIdentity, window chrome.ControlBadgeWindow) func() {
	gateway := h.nativeByUser[p.Namespace]
	if gateway == nil || filepath.Base(process.Executable) != "Google Chrome" {
		return nil
	}
	token := credentialID()
	if token == "" {
		return nil
	}
	target := native.ControlBadgeTarget{BundleID: "com.google.Chrome", ProcessID: process.PID, ProcessStartToken: process.StartToken, WindowBounds: native.CaptureBounds{X: window.X, Y: window.Y, Width: window.Width, Height: window.Height}}
	begin, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	shown, err := gateway.BeginControlBadge(begin, p, token, target, 3*time.Second)
	cancel()
	if err != nil || shown.Status == "unavailable" {
		// A presentation reply can be lost after the panel was shown. End this
		// exact token; never retry begin or affect a newer operation's badge.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 500*time.Millisecond)
		defer cancel()
		_, _ = gateway.StopControlBadge(cleanup, p, token)
		return nil
	}
	lifetime, stop := context.WithCancel(ctx)
	var once sync.Once
	finish := func(immediate bool) {
		once.Do(func() {
			stop()
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 500*time.Millisecond)
			defer cancel()
			if immediate {
				_, _ = gateway.StopControlBadge(cleanup, p, token)
			} else {
				_, _ = gateway.EndControlBadge(cleanup, p, token)
			}
		})
	}
	end := func() { finish(false) }
	go func() {
		defer func() { finish(false) }()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-ticker.C:
				renew, cancel := context.WithTimeout(lifetime, 500*time.Millisecond)
				renewed, err := gateway.RenewControlBadge(renew, p, token, 3*time.Second)
				cancel()
				if err != nil || renewed.Status == "unavailable" {
					finish(true)
					return
				}
			}
		}
	}()
	return end
}
