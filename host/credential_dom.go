package host

import (
	"context"
	"errors"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

// Only an independently qualified backend proof may construct this state. It is
// deliberately volatile: the durable protection ledger remains held. A restart,
// disconnect, document change or unknown attempt cannot recover it from JSON.
type credentialDOMState struct {
	authority chrome.ControlAuthority
	verify    func(context.Context, auth.Principal, model.Surface, bool) error
}

func (s *credentialService) authorizeDOM(ctx context.Context, p auth.Principal, surface model.Surface, mutation bool, requested consent.Mode) (*consent.Lease, error) {
	denied := func() (*consent.Lease, error) { return nil, vault.ErrDeliveryProtected }
	if !s.available() || surface.Kind != "web" || surface.Origin == "" || surface.BundleID != "" || surface.ProcessID != 0 || surface.ProcessStartToken != "" || surface.Title != "" || requested != consent.Observe && requested != consent.Control || auth.NativeHuman(ctx) {
		return denied()
	}
	cb, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || cb.SessionID == "" {
		return denied()
	}
	s.mu.Lock()
	var item *credentialSession
	if !s.closed {
		for _, candidate := range s.pending {
			if candidate.actor.Namespace == p.Namespace && candidate.actor.ClientID == p.ClientID && candidate.consent.SessionID == cb.SessionID && candidate.target.Origin == surface.Origin {
				if item != nil {
					s.mu.Unlock()
					return denied()
				}
				item = candidate
			}
		}
	}
	s.mu.Unlock()
	if item == nil {
		return denied()
	}
	// Do not hold item.mu across a new durable consent lookup: normal execution
	// already owns the user lock; private operations use user-lock then item-lock.
	item.mu.Lock()
	dom, protected := item.dom, item.protected
	binding := item.binding
	expectedConsent := item.consent
	valid := dom != nil && dom.verify != nil && protected != nil && !item.uncertain && item.state == "privacyReady" && item.done != nil && item.done.Err() == nil
	if valid {
		valid = surface.Origin == dom.authority.Document.Origin && (surface.TabID == "" || surface.TabID == dom.authority.Document.QualifiedTabID())
	}
	item.mu.Unlock()
	if !valid {
		return denied()
	}
	lease, e := s.host.authorizeConsentOperation(ctx, p, surface, mutation, requested)
	if e != nil {
		return denied()
	}
	actualBinding, bound := auth.ConsentBindingFromContext(lease.Context)
	if !bound || actualBinding != expectedConsent {
		// Diagnose only a purpose-only mismatch after normal durable consent
		// resolved the same grant/session for this exact promoted target. This
		// grants no DOM permit and never exposes either purpose string.
		purposeOnly := bound && actualBinding.GrantID == expectedConsent.GrantID && actualBinding.SessionID == expectedConsent.SessionID && actualBinding.Purpose != expectedConsent.Purpose
		item.mu.Lock()
		stillCurrent := item.dom == dom && item.protected == protected && item.consent == expectedConsent && !item.uncertain && item.state == "privacyReady" && item.done != nil && item.done.Err() == nil
		item.mu.Unlock()
		lease.Release()
		if purposeOnly && stillCurrent {
			return nil, &model.MechanizeError{Code: "credentialPurposeMismatch", Message: "Use the original credential preparation session, grant and purpose for this protected document", Stage: "consent", DispatchState: "notDispatched", EffectState: "none"}
		}
		return denied()
	}
	guarded, cancel := context.WithCancel(lease.Context)
	stop := context.AfterFunc(item.done, cancel)
	release, e := protected.AcquireDOM(guarded, binding, func(c context.Context) error {
		if s.host.Runtime.CheckSession(c, p, item.consent.SessionID) != nil {
			return errPrivateCredential
		}
		return dom.verify(c, p, surface, mutation)
	})
	if e != nil {
		stop()
		cancel()
		lease.Release()
		return denied()
	}
	item.mu.Lock()
	valid = item.dom == dom && item.protected == protected && !item.uncertain && item.state == "privacyReady" && item.done.Err() == nil
	item.mu.Unlock()
	if !valid {
		release()
		stop()
		cancel()
		lease.Release()
		return denied()
	}
	previous := lease.Release
	lease.Context = guarded
	lease.Release = func() { release(); stop(); cancel(); previous() }
	return lease, nil
}

func (s *credentialService) verifyDOMStatus(ctx context.Context, p auth.Principal, item *credentialSession) error {
	if item.dom == nil || item.dom.verify == nil || item.protected == nil || item.uncertain || item.done == nil || item.done.Err() != nil {
		return errPrivateCredential
	}
	surface := model.Surface{Kind: "web", Origin: item.dom.authority.Document.Origin, TabID: item.dom.authority.Document.QualifiedTabID()}
	changed := false
	release, e := item.protected.AcquireDOM(ctx, item.binding, func(c context.Context) error {
		err := item.dom.verify(c, p, surface, false)
		changed = errors.Is(err, chrome.ErrCredentialPrivacyDocumentChanged)
		return err
	})
	if e != nil {
		if changed && !item.manualDOM {
			return s.qualifyDOM(ctx, p, item)
		}
		item.state = "needsNativeAction"
		item.attention = "postLoginDocumentUnavailable"
		return errPrivateCredential
	}
	release()
	item.attention = ""
	item.state = "privacyReady"
	item.stage = "privacyReady"
	return nil
}
