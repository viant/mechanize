package host

import (
	"context"
	"errors"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

type credentialScopeBrowser interface {
	CaptureCredentialProtectionScope(context.Context, auth.Principal, chrome.ControlAuthority, string) (chrome.CredentialProtectionScope, error)
	VerifyProtectionDisjoint(context.Context, auth.Principal, chrome.CredentialProtectionScope, model.Surface) error
	VerifyCredentialScopeAbsent(context.Context, auth.Principal, chrome.CredentialProtectionScope) error
	RetireAbsentCredentialScope(context.Context, auth.Principal, chrome.CredentialProtectionScope) error
}

func (h *Host) credentialScopeBrowser() credentialScopeBrowser {
	if h.credentials != nil && h.credentials.browserFixture != nil {
		v, _ := h.credentials.browserFixture.(credentialScopeBrowser)
		return v
	}
	if h.chrome == nil {
		return nil
	}
	return h.chrome
}
func protectionScopeRecord(p auth.Principal, s chrome.CredentialProtectionScope) data.CredentialProtectionScopeRecord {
	return data.CredentialProtectionScopeRecord{Namespace: p.Namespace, ClientID: p.ClientID, PreparationID: s.PreparationID, Origin: s.Origin, ProfileChannel: s.Identity.ProfileChannel, BrowserInstance: s.Identity.BrowserInstance, TabID: s.Identity.TabID, FrameID: s.Identity.FrameID, DocumentID: s.Identity.DocumentID, DocumentGeneration: int(s.Identity.Generation), ChromeStartToken: s.ChromeStartToken, BrokerEpoch: s.BrokerEpoch, ChannelEpoch: s.ChannelEpoch, ScopeHash: s.ScopeHash, LoginRouteSHA256: s.LoginRouteSHA256, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
}
func sourceFromProtection(p auth.Principal, snapshot durable.CredentialProtection) chrome.CredentialProtectionScope {
	r := snapshot.Scope
	if snapshot.LegacySource != nil {
		r = *snapshot.LegacySource
	}
	out := chrome.CredentialProtectionScope{PreparationID: r.PreparationID, Origin: r.Origin}
	if r.Exact() {
		out.Identity = chrome.Identity{ProfileChannel: r.ProfileChannel, BrowserInstance: r.BrowserInstance, TabID: r.TabID, FrameID: r.FrameID, DocumentID: r.DocumentID, Generation: uint64(r.DocumentGeneration)}
		out.ChromeStartToken = r.ChromeStartToken
		out.BrokerEpoch = r.BrokerEpoch
		out.ChannelEpoch = r.ChannelEpoch
		out.ScopeHash = r.ScopeHash
		out.LoginRouteSHA256 = r.LoginRouteSHA256
		return out
	}
	// Owned immutable delivery rows can supply a legacy source. They never prove
	// it absent: the fresh backend verifier must independently establish that.
	prep, rows := snapshot.Preparation, snapshot.Attempts
	if r.ClientID != p.ClientID || prep.PreparationID != r.PreparationID || prep.Origin != r.Origin || prep.Namespace != p.Namespace || prep.ClientID != p.ClientID || prep.ProtectionState != "held" || prep.Revision != 1 || len(rows) == 0 {
		return out
	}
	first := rows[0]
	for _, v := range rows {
		if v.Namespace != p.Namespace || v.ClientID != p.ClientID || v.SelectionID != prep.PreparationID || v.Origin != prep.Origin || v.SessionID != prep.SessionID || v.GrantID != prep.GrantID || v.PurposeHash != prep.PurposeHash || v.SelectedRevision != prep.SelectedRevision || v.ProfileChannel == "" || v.ProfileChannel != first.ProfileChannel || v.BrowserInstance == "" || v.BrowserInstance != first.BrowserInstance || v.TabID <= 0 || v.TabID != first.TabID || v.DocumentID == "" || v.DocumentID != first.DocumentID || v.DocumentGeneration < 1 || v.ChromeStartToken == "" || v.ChromeStartToken != first.ChromeStartToken || v.Revision < 1 || v.DispatchState != "unknown" && v.DispatchState != "dispatched" && v.DispatchState != "notDispatched" {
			return out
		}
	}
	out.Identity = chrome.Identity{ProfileChannel: first.ProfileChannel, BrowserInstance: first.BrowserInstance, TabID: first.TabID, FrameID: 0, DocumentID: first.DocumentID, Generation: uint64(first.DocumentGeneration)}
	out.ChromeStartToken = first.ChromeStartToken
	out.BrokerEpoch = first.BrokerEpoch
	out.ChannelEpoch = first.ChannelEpoch
	out.ScopeHash = first.ScopeHash
	return out
}
func (s *credentialService) captureProtectionScope(ctx context.Context, p auth.Principal, item *credentialSession, a chrome.ControlAuthority) error {
	backend := s.host.credentialScopeBrowser()
	if backend == nil {
		return errPrivateCredential
	}
	scope, e := backend.CaptureCredentialProtectionScope(ctx, p, a, item.id)
	if e != nil || scope.PreparationID != item.id || scope.Identity != a.Document.Identity || scope.Origin != item.target.Origin || scope.ChromeStartToken != a.Evidence.ChromeParent.StartToken || scope.BrokerEpoch != a.BrokerEpoch || scope.ChannelEpoch != a.ChannelEpoch || scope.ScopeHash != a.ScopeHash {
		return errPrivateCredential
	}
	sealed, stop, e := data.WithCredentialProtectionScopeAuthority(ctx, protectionScopeRecord(p, scope))
	if e != nil {
		return e
	}
	defer stop()
	if e = s.host.durable.ReserveCredentialProtectionScope(sealed, p); e != nil {
		return e
	}
	item.protectionScope = scope
	return nil
}
func (h *Host) authorizeDisjointWeb(ctx context.Context, p auth.Principal, surface model.Surface, mutation bool, requested consent.Mode, scopes []durable.CredentialProtection) (*consent.Lease, error) {
	if surface.Kind != "web" || surface.Origin == "" || surface.TabID == "" || surface.BundleID != "" || surface.Title != "" || surface.ProcessID != 0 || surface.ProcessStartToken != "" || requested != consent.Observe && requested != consent.Control || auth.NativeHuman(ctx) {
		return nil, vault.ErrDeliveryProtected
	}
	backend := h.credentialScopeBrowser()
	if backend == nil {
		return nil, vault.ErrDeliveryProtected
	}
	lease, e := h.authorizeConsentOperation(ctx, p, surface, mutation, requested)
	if e != nil {
		return nil, e
	}
	var verificationError error
	verify := func(c context.Context, binding vault.Binding) error {
		matchedBinding := binding.DocumentID == ""
		for _, snapshot := range scopes {
			source := sourceFromProtection(p, snapshot)
			if binding.DocumentID != "" && source.PreparationID == binding.Target.Account && source.Origin == binding.Target.Origin && h.credentials != nil {
				h.credentials.mu.Lock()
				item := h.credentials.pending[source.PreparationID]
				h.credentials.mu.Unlock()
				if item != nil {
					exposure := item.exposure.Load()
					if exposure != nil && exposure.binding == binding && exposure.surface.TabID != "" && exposure.surface.TabID != surface.TabID {
						matchedBinding = true
					}
				}
			}
			if e := backend.VerifyProtectionDisjoint(c, p, source, surface); e != nil {
				verificationError = e
				return e
			}
		}
		if !matchedBinding {
			return vault.ErrDeliveryProtected
		}
		return c.Err()
	}
	var release func()
	if h.vaultExposure != nil {
		release, e = h.vaultExposure.AcquireScopedWebExposure(lease.Context, verify)
	} else {
		e = verify(lease.Context, vault.Binding{})
	}
	if e != nil {
		lease.Release()
		// The exposure gate retains exclusion, but its generic refusal must not
		// turn a closed stale/transport proof failure into a private-page claim.
		if verificationError != nil && !errors.Is(verificationError, vault.ErrDeliveryProtected) && !errors.Is(verificationError, vault.ErrEntryProtected) {
			e = credentialPublicReadFailure(chrome.CredentialProtectionFailureReason(verificationError))
		}
		if errors.Is(e, vault.ErrDeliveryProtected) || errors.Is(e, vault.ErrEntryProtected) {
			return nil, errors.Join(e, &model.MechanizeError{Code: "privateDOMUnavailable", Message: "Credential protection excludes this document exposure.", Stage: "admission", DispatchState: "notDispatched", EffectState: "none"})
		}
		return nil, e
	}
	if release != nil {
		previous := lease.Release
		lease.Release = func() { defer release(); previous() }
	}
	return lease, nil
}
