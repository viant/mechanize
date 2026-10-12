package host

import (
	"context"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
)

func (h *Host) configureWebControl(ctx context.Context, c Config, options HostOptions) error {
	h.chromeAllWebsites = map[string]bool{}
	if c.Chrome != nil {
		for _, grant := range c.Chrome.Grants {
			if grant.AllWebsites && len(grant.Origins) == 0 && h.users[grant.Principal.Namespace].DesktopAccess {
				h.chromeAllWebsites[grant.Principal.Namespace] = true
			}
		}
	}
	if h.chromeStartupUnqualified {
		return nil
	}
	if options.WebControl == nil {
		if c.Chrome == nil || c.Chrome.FixtureEnrollment || h.chrome == nil {
			return nil
		}
		options.WebControl = h.productionWebControl()
	}
	enrolled := *options.WebControl
	if h.chrome != nil && enrolled.CapabilityProbe == nil {
		enrolled.CapabilityProbe = h.chrome.ControlCapabilitiesFor
	}
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
			if scopeErr != nil || (trustScope == chrome.TrustScopeDesktop || grant.AllWebsites) && !user.DesktopAccess || grant.AllWebsites && len(grant.Origins) != 0 {
				continue
			}
			if grant.Principal.Namespace != p.Namespace || !grant.Principal.HasScope("desktop:control") {
				continue
			}
			profile := WebControlProfile{AllWebsites: grant.AllWebsites, TrustScope: trustScope, ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, ExtensionOrigin: grant.ExtensionOrigin}
			for _, origin := range grant.Origins {
				allowed := user.DesktopAccess
				for _, ceiling := range user.WebOrigins {
					allowed = allowed || ceiling == origin
				}
				if allowed {
					profile.Origins = append(profile.Origins, origin)
				}
			}
			if profile.AllWebsites && h.chrome != nil {
				inventory, e := h.chrome.ListTabs(ctx, p)
				if e == nil && inventory.Complete {
					seen := map[string]bool{}
					for _, d := range inventory.Documents {
						if d.ProfileChannel == profile.ProfileChannel && d.BrowserInstance == profile.BrowserInstance && !seen[d.Origin] && chrome.OrdinaryWebsiteOrigin(d.Origin) {
							seen[d.Origin] = true
							profile.ObservedOrigins = append(profile.ObservedOrigins, d.Origin)
						}
					}
				}
			}
			if profile.AllWebsites || len(profile.Origins) > 0 {
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
	if step.Action == "browser.activateTab" {
		return h.prepareActivateTab(ctx, p, step)
	}
	if step.Action == "browser.openOrigin" {
		return h.prepareOpenOrigin(ctx, p, step)
	}
	if step.Target.Surface.Kind == "web" {
		if h.webControl == nil {
			return nil, 0, ErrWebControlUnqualified
		}
		// Reusable trust must be pinned before the durable web intent. Lookup
		// selects an existing human grant; Execute still reauthorizes it.
		binding, ok := auth.ConsentBindingFromContext(ctx)
		if ok && binding.GrantID == "" && binding.Purpose != "" && h.consent != nil {
			scope, err := h.operationConsentScope(p, step.Target.Surface)
			if err != nil {
				return ctx, 0, err
			}
			grant, err := h.consent.FindPermanentGrant(ctx, p, consent.Operation{SessionID: binding.SessionID, Scope: scope, Mode: consent.Control, Purpose: binding.Purpose})
			if err != nil {
				return ctx, 0, err
			}
			if grant == nil {
				return ctx, 0, &model.MechanizeError{Code: "permissionRequired", Stage: "consent", DispatchState: "notDispatched", Message: "Approve this session or trust this verified tool until revoked"}
			}
			binding.GrantID = grant.ID
			ctx = auth.WithConsentBinding(ctx, binding)
		}
		return h.webControl.Prepare(ctx, p, step)
	}
	if step.Target.Surface.Kind != "native" {
		return nil, 0, ErrNativeControlUnqualified
	}
	return h.prepareNativeStepExecutor(ctx, p, step)
}
