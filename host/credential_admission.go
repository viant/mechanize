package host

import (
	"context"
	"errors"
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

type credentialAdmissionFailure struct {
	reason string
	cause  error
}

func (e *credentialAdmissionFailure) Error() string                     { return "credential admission unavailable" }
func (e *credentialAdmissionFailure) Unwrap() error                     { return e.cause }
func (e *credentialAdmissionFailure) CredentialAdmissionReason() string { return e.reason }
func credentialAdmissionAt(reason string, cause error) error {
	return &credentialAdmissionFailure{reason: reason, cause: errors.Join(errPrivateCredential, cause)}
}

func (s *credentialService) proofAdmission(item *credentialSession) func(context.Context) error {
	return func(ctx context.Context) error {
		if s == nil || item == nil || s.done == nil || s.done.Err() != nil || item.done == nil || item.done.Err() != nil || ctx.Err() != nil {
			return credentialAdmissionAt("credentialLifetime", ctx.Err())
		}
		p, e := auth.FromContext(ctx)
		cb, ok := auth.ConsentBindingFromContext(ctx)
		if e != nil || p.Validate() != nil || p.Namespace != item.actor.Namespace || p.ClientID != item.actor.ClientID || !p.HasScope("desktop:control") || auth.NativeHuman(ctx) {
			return credentialAdmissionAt("credentialActor", e)
		}
		if !ok || cb != item.consent {
			return credentialAdmissionAt("credentialBinding", nil)
		}
		if e := s.host.Runtime.CheckSession(ctx, p, cb.SessionID); e != nil {
			return credentialAdmissionAt("credentialSession", e)
		}
		exposure := item.exposure.Load()
		if exposure == nil || exposure.lease == nil {
			return credentialAdmissionAt("credentialExposure", nil)
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
		if e := verify(); e != nil {
			return credentialAdmissionAt("credentialLease", e)
		}
		lease, e := s.host.authorizeConsentOperation(ctx, p, exposure.surface, true, consent.Control)
		if e != nil {
			return credentialAdmissionAt("credentialConsent", e)
		}
		defer lease.Release()
		if e := lease.Context.Err(); e != nil {
			return credentialAdmissionAt("credentialConsent", e)
		}
		if item.exposure.Load() != exposure {
			return credentialAdmissionAt("credentialExposureChanged", nil)
		}
		if e := verify(); e != nil {
			return credentialAdmissionAt("credentialLease", e)
		}
		return nil
	}
}
