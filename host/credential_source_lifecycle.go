package host

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/vault"
	"strings"
)

type credentialSupersededSourceBrowser interface {
	VerifyCredentialSourceSuperseded(context.Context, auth.Principal, chrome.CredentialProtectionScope) error
}

type credentialControllerIdleBrowser interface {
	VerifyCredentialSourceIdle(context.Context, auth.Principal) error
}

// Explicit Prepare may retire an idle predecessor's privacy protection only.
// Non-controller predecessors require completed runtime close or authenticated
// executor supersession across restart before the independent source-absence proof.
// The real successor remains the actor; no old delivery capability is restored.
func (s *credentialService) retireIdleControllerSource(ctx context.Context, p auth.Principal, snapshot durable.CredentialProtection) error {
	h := s.host
	backend := h.credentialScopeBrowser()
	owners, ok := backend.(credentialControllerIdleBrowser)
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if !ok || !bound || !snapshot.Scope.Exact() {
		return errOtherCredentialScopeHeld
	}
	s.mu.Lock()
	old := s.pending[snapshot.Scope.PreparationID]
	s.mu.Unlock()
	if old != nil {
		if !old.mu.TryLock() {
			return chrome.ErrCredentialSourceInputBusy
		}
		defer old.mu.Unlock()
		if old.actor.Namespace != snapshot.Scope.Namespace || old.actor.ClientID != snapshot.Scope.ClientID || old.id != snapshot.Scope.PreparationID || old.target.Origin != snapshot.Scope.Origin || old.target.Account != snapshot.Scope.PreparationID {
			return errOtherCredentialScopeHeld
		}
	}
	controllerOwner := strings.HasPrefix(snapshot.Scope.ClientID, "controller:")
	var superseded credentialSupersededSourceBrowser
	var originalSource chrome.CredentialProtectionScope
	if !controllerOwner && old == nil {
		var supported bool
		superseded, supported = backend.(credentialSupersededSourceBrowser)
		if !supported {
			return errOtherCredentialScopeHeld
		}
		scope := snapshot.Scope
		originalSource = chrome.CredentialProtectionScope{PreparationID: scope.PreparationID, Origin: scope.Origin, Identity: chrome.Identity{ProfileChannel: scope.ProfileChannel, BrowserInstance: scope.BrowserInstance, TabID: scope.TabID, FrameID: scope.FrameID, DocumentID: scope.DocumentID, Generation: uint64(scope.DocumentGeneration)}, ChromeStartToken: scope.ChromeStartToken, BrokerEpoch: scope.BrokerEpoch, ChannelEpoch: scope.ChannelEpoch, ScopeHash: scope.ScopeHash, LoginRouteSHA256: scope.LoginRouteSHA256}
	}
	inputIdle := func(c context.Context) error {
		if c.Err() != nil || h.Runtime.CheckSession(c, p, binding.SessionID) != nil {
			return errPrivateCredential
		}
		if !controllerOwner {
			if old != nil {
				if old.done == nil || old.done.Err() == nil || h.Runtime.CheckPredecessorSessionStopped(c, p, old.actor.Namespace, old.actor.ClientID, old.consent.SessionID) != nil {
					return errOtherCredentialScopeHeld
				}
			} else if e := superseded.VerifyCredentialSourceSuperseded(c, p, originalSource); e != nil {
				return e
			}
		}
		return owners.VerifyCredentialSourceIdle(c, p)
	}
	// Preserve the finite original guard cause before the sealed boolean checker.
	if e := inputIdle(ctx); e != nil {
		return e
	}
	sealed, revoke, e := data.WithCredentialSourceLifecycleAuthority(ctx, snapshot.Scope, inputIdle)
	if e != nil {
		return e
	}
	defer revoke()
	prep, children, e := h.durable.LoadCredentialRecovery(sealed, p, snapshot.Scope.PreparationID)
	if e != nil || !controllerOwner && old != nil && prep.SessionID != old.consent.SessionID || prep.Namespace != snapshot.Scope.Namespace || prep.ClientID != snapshot.Scope.ClientID || prep.Origin != snapshot.Scope.Origin || prep.PreparationID != snapshot.Scope.PreparationID || !(prep.ProtectionState == "held" && prep.Revision == 1 || prep.ProtectionState == "closed" && prep.Revision == 2) {
		return errOtherCredentialScopeHeld
	}
	snapshot.Preparation, snapshot.Attempts = prep, children
	sources, e := protectionAbsenceSourcesForOwner(snapshot)
	if e != nil {
		return e
	}
	if old != nil {
		// Manual staging retains its existing extra B-absence requirement.
		// Automatic privacyReady retires only A-derived authority, not B.
		successor, e := manualSuccessorProtectionLocked(old.actor, snapshot, old)
		if e != nil {
			return e
		}
		if successor != nil {
			sources = append(sources, *successor)
		}
	}
	finishProcesses := func(c context.Context) error { return c.Err() }
	if pin, ok := backend.(interface {
		PinCredentialScopeProcesses(context.Context, auth.Principal, []chrome.CredentialProtectionScope) (context.Context, func(context.Context) error, error)
	}); ok {
		pinned, finish, e := pin.PinCredentialScopeProcesses(sealed, p, sources)
		if e != nil {
			return e
		}
		if pinned == nil || finish == nil {
			return errPrivateCredential
		}
		sealed = pinned
		finishProcesses = finish
	}
	guard := func(c context.Context) error {
		if e := inputIdle(c); e != nil {
			return e
		}
		for _, source := range sources {
			if e := backend.VerifyCredentialScopeAbsent(c, p, source); e != nil {
				return e
			}
		}
		return c.Err()
	}
	if e = guard(sealed); e != nil {
		return e
	}
	clean, stop, e := data.WithCredentialSourceAbsenceAuthority(sealed, prep, children, credentialRetirementSourceRecords(p, snapshot, sources), guard)
	if e != nil {
		return e
	}
	defer stop()
	retire := func(c context.Context) error {
		if e := guard(c); e != nil {
			return e
		}
		if old != nil {
			if old.cancel != nil {
				old.cancel()
			}
			if old.selection != nil {
				old.selection.Revoke()
			}
			old.dom = nil
			old.state = "needsNativeAction"
			old.attention = "scopeSourceRetirement"
		}
		if e := h.retireCredentialSourceRows(c, p, snapshot, sources, guard); e != nil {
			return e
		}
		return finishProcesses(c)
	}
	if old != nil {
		var e error
		if old.protected != nil {
			e = old.protected.RecoverRetired(clean, guard, retire)
		} else if old.preparation != nil {
			e = old.preparation.RecoverRetired(clean, guard, retire)
		} else {
			return errPrivateCredential
		}
		if e != nil && !errors.Is(e, vault.ErrRetiredDeliveryAbsent) {
			if cause := guard(clean); cause != nil {
				return cause
			}
			return e
		}
		if e == nil {
			return nil
		}
	}
	release, e := h.vaultExposure.AcquireExposureContext(clean)
	if e != nil {
		return e
	}
	defer release()
	return retire(clean)
}
