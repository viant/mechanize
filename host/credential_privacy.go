package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

// qualifyDOM is the sole production constructor of credentialDOMState. Neither
// a caller stage string nor absence of a form can activate ordinary routing.
// The backend's opaque live proof includes retired private authority and actual
// persistent redaction on a separately qualified new same-origin document.
func (s *credentialService) qualifyDOM(ctx context.Context, p auth.Principal, item *credentialSession) error {
	item.attention = "postSubmitPrivacyAdmissionUnavailable"
	if item.protected == nil || item.submitAttempt == "" || item.uncertain || item.dispatch != "dispatched" || len(item.attempts) < 2 {
		return errPrivateCredential
	}
	for _, a := range item.attempts {
		if a.DispatchState != "dispatched" || a.ProtectionState != "held" || a.Revision != 2 {
			return errPrivateCredential
		}
	}
	var proof chrome.CredentialPrivacyProof
	var authority chrome.ControlAuthority
	binding, protected, e := item.protected.TransitionDOM(ctx, item.binding, func(c context.Context) (vault.Binding, error) {
		item.attention = "postSubmitPrivacyPromotionUnavailable"
		var e error
		proof, e = s.browser().QualifyCredentialPrivacy(c, p, item.authority, item.submitAttempt, s.proofAdmission(item))
		if e != nil {
			item.attention = chrome.CredentialPrivacyFailureCode(e)
			return vault.Binding{}, errPrivateCredential
		}
		var valid bool
		authority, valid = proof.Authority()
		if !valid || authority.Owner != item.actor.Namespace || authority.ClientID != item.actor.ClientID || authority.Document.Origin != item.target.Origin || authority.Document.TabID != item.authority.Document.TabID || authority.Document.ProfileChannel != item.authority.Document.ProfileChannel || authority.Document.BrowserInstance != item.authority.Document.BrowserInstance {
			return vault.Binding{}, errPrivateCredential
		}
		return vault.Binding{SessionID: item.consent.SessionID, DocumentID: authority.Document.DocumentID, NavigationID: chrome.CredentialNavigationID(authority), Target: item.target}, nil
	})
	if e != nil {
		return errPrivateCredential
	}
	item.binding = binding
	item.protected = protected
	item.authority = authority
	// Publish new held exposure before any normal backend verification can invoke
	// its persistent callback. No old request context survives this transition.
	item.publishExposure(true)
	item.dom = &credentialDOMState{authority: authority, verify: func(c context.Context, actor auth.Principal, surface model.Surface, mutation bool) error {
		return s.browser().VerifyCredentialPrivacy(c, actor, proof, surface, mutation)
	}}
	item.state = "privacyReady"
	item.stage = "privacyReady"
	item.attention = ""
	return nil
}

func closedCredentialPrivacyAttention(code string) bool {
	switch code {
	case "postSubmitPrivacyNotReady", "postSubmitPrivacyUnavailable", "postSubmitPrivacyAdmissionUnavailable", "postSubmitPrivacyFenceUnavailable", "postSubmitPrivacyReplyUnavailable", "postSubmitPrivacyCommitUnavailable", "postSubmitPrivacyProbeUnavailable", "postSubmitPrivacyPromotionUnavailable":
		return true
	}
	return false
}
