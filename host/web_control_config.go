package host

import (
	"context"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
)

func (h *Host) configureWebControl(ctx context.Context, c Config, options HostOptions) error {
	if options.WebControl == nil {
		if c.Chrome == nil || c.Chrome.FixtureEnrollment || h.chrome == nil {
			return nil
		}
		options.WebControl = h.productionWebControl()
	}
	enrolled := *options.WebControl
	enrolled.Owner = ctx
	enrolled.authorizeRead = func(ctx context.Context, p auth.Principal, surface model.Surface) (*consent.Lease, error) {
		return h.AuthorizeOperation(ctx, p, surface, false, consent.Observe)
	}
	enrolled.Authorize = func(ctx context.Context, p auth.Principal, surface model.Surface) (*consent.Lease, error) {
		return h.AuthorizeOperation(ctx, p, surface, true, consent.Control)
	}
	enrolled.Enrolled = func(ctx context.Context, p auth.Principal) (WebControlScope, error) {
		user, err := h.authorize(ctx, p)
		if err != nil {
			return WebControlScope{}, err
		}
		var scope WebControlScope
		if c.Chrome == nil {
			return scope, nil
		}
		for _, grant := range c.Chrome.Grants {
			trustScope, scopeErr := chrome.NormalizeTrustScope(grant.TrustScope)
			if scopeErr != nil || trustScope == chrome.TrustScopeDesktop && !user.DesktopAccess {
				continue
			}
			if grant.Principal.Namespace != p.Namespace || !grant.Principal.HasScope("desktop:control") {
				continue
			}
			profile := WebControlProfile{TrustScope: trustScope, ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, ExtensionOrigin: grant.ExtensionOrigin}
			for _, origin := range grant.Origins {
				allowed := user.DesktopAccess
				for _, ceiling := range user.WebOrigins {
					allowed = allowed || ceiling == origin
				}
				if allowed {
					profile.Origins = append(profile.Origins, origin)
				}
			}
			if len(profile.Origins) > 0 {
				scope.Profiles = append(scope.Profiles, profile)
			}
		}
		return scope, nil
	}
	manager, err := NewWebControlManager(enrolled)
	if err != nil {
		return err
	}
	h.webControl = manager
	return nil
}

// Endly calls durable execution; this provider only pins the right executor
// before the generated intent writer. It does not dispatch or schedule work.
func (h *Host) prepareStepExecutor(ctx context.Context, p auth.Principal, step model.Step) (context.Context, int, error) {
	if step.Target.Surface.Kind == "web" {
		if h.webControl == nil {
			return nil, 0, ErrWebControlUnqualified
		}
		return h.webControl.Prepare(ctx, p, step)
	}
	if step.Target.Surface.Kind != "native" {
		return nil, 0, ErrNativeControlUnqualified
	}
	epoch, err := h.controlLeaseEpoch(ctx, p)
	return ctx, epoch, err
}
