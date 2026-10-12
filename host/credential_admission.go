package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

// Published as one immutable pointer so backend proof callbacks never take
// item.mu while host qualification already holds it. The outer lock order is
// durable user -> credential item -> exposure/browser. No callback retains an
// MCP request context, old held-user token or expired request consent lease.
type credentialExposure struct {
	lease     *vault.DeliveryLease
	binding   vault.Binding
	surface   model.Surface
	dom       bool
	submitted bool
}

func (item *credentialSession) publishExposure(dom bool) {
	item.exposure.Store(&credentialExposure{lease: item.protected, binding: item.binding, surface: model.Surface{Kind: "web", Origin: item.authority.Document.Origin, TabID: item.authority.Document.QualifiedTabID()}, dom: dom, submitted: item.metadataContinuation()})
}
func (s *credentialService) proofAdmission(item *credentialSession) func(context.Context) error {
	return func(ctx context.Context) error {
		if s == nil || item == nil || s.done == nil || s.done.Err() != nil || item.done == nil || item.done.Err() != nil || ctx.Err() != nil {
			return errPrivateCredential
		}
		p, e := auth.FromContext(ctx)
		cb, ok := auth.ConsentBindingFromContext(ctx)
		if e != nil || p.Validate() != nil || p.Namespace != item.actor.Namespace || p.ClientID != item.actor.ClientID || !p.HasScope("desktop:control") || auth.NativeHuman(ctx) || !ok || cb != item.consent || s.host.Runtime.CheckSession(ctx, p, cb.SessionID) != nil {
			return errPrivateCredential
		}
		exposure := item.exposure.Load()
		if exposure == nil || exposure.lease == nil {
			return errPrivateCredential
		}
		verify := func() error {
			if exposure.dom {
				return exposure.lease.VerifyDOM(ctx, exposure.binding)
			}
			if item.selection == nil {
				return errPrivateCredential
			}
			var selected error
			if exposure.submitted {
				selected = item.selection.VerifyPrivacyBinding(ctx, exposure.binding)
			} else {
				selected = item.selection.Verify(ctx, exposure.binding)
			}
			if selected != nil {
				return errPrivateCredential
			}
			return exposure.lease.Verify(ctx, exposure.binding)
		}
		if verify() != nil {
			return errPrivateCredential
		}
		lease, e := s.host.authorizeConsentOperation(ctx, p, exposure.surface, true, consent.Control)
		if e != nil {
			return errPrivateCredential
		}
		defer lease.Release()
		if lease.Context.Err() != nil || item.exposure.Load() != exposure || verify() != nil {
			return errPrivateCredential
		}
		return nil
	}
}
