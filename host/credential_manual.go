package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
	"sync/atomic"
	"time"
)

// CredentialResumeManual neither logs in nor infers login success. Source
// provenance comes solely from owned immutable delivery rows; fresh manual DOM
// output requires its own private redactor proof and a current reusable grant.
func (h *Host) CredentialResumeManual(ctx context.Context, p auth.Principal, in gateway.CredentialRefInput) (gateway.CredentialResult, error) {
	out := gateway.CredentialResult{PreparationID: in.PreparationID, State: "needsNativeAction", AttentionCode: "postSubmitPrivacyUnavailable"}
	if h == nil || h.credentials == nil || h.chrome == nil || h.durable == nil || h.Runtime.CheckSession(ctx, p, in.SessionID) != nil || len(in.PreparationID) != 64 {
		return out, errPrivateCredential
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	phase := "source"
	e := h.durable.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
		prep, rows, e := h.durable.LoadCredentialRecovery(held, p, in.PreparationID)
		if e != nil || prep.ProtectionState != "held" || prep.Revision != 1 || len(rows) == 0 {
			return errPrivateCredential
		}
		source, e := manualCredentialSource(p, prep, rows)
		if e != nil {
			return e
		}
		first := rows[0]
		surface := model.Surface{Kind: "web", Origin: prep.Origin}
		desired := auth.WithConsentBinding(held, auth.ConsentBinding{SessionID: in.SessionID, Purpose: "Resume redacted browser observation after manual login"})
		phase = "consent"
		lease, e := h.authorizeConsentOperation(consent.RequireReusableGrant(desired), p, surface, true, consent.Control)
		if e != nil {
			return e
		}
		defer lease.Release()
		working := lease.Context
		cb, ok := auth.ConsentBindingFromContext(working)
		if !ok {
			return errPrivateCredential
		}
		admission := &manualCleanupAdmission{host: h, actor: p, sessionID: in.SessionID, surface: surface, binding: cb, lease: lease}
		baseGuard := admission.check

		var exposure atomic.Pointer[credentialExposure]
		proofGuard := func(c context.Context) error {
			if baseGuard(c) != nil {
				return errPrivateCredential
			}
			if held := exposure.Load(); held != nil {
				if held.dom {
					return held.lease.VerifyDOM(c, held.binding)
				}
				return held.lease.Verify(c, held.binding)
			}
			return nil
		}

		phase = "absence"
		transition, e := h.chrome.BeginManualCredentialPrivacy(working, p, source, proofGuard)
		if e != nil {
			return e
		}
		defer transition.Abort()
		// Retire a retained old volatile capability only after independently confirmed
		// source-tab absence; replacing the gate below never exposes the desktop.
		h.credentials.mu.Lock()
		old := h.credentials.pending[in.PreparationID]
		h.credentials.mu.Unlock()
		if old != nil {
			old.mu.Lock()
			if old.actor.Namespace != p.Namespace || old.actor.ClientID != p.ClientID || old.uncertain {
				old.mu.Unlock()
				return errPrivateCredential
			}
			if old.cancel != nil {
				old.cancel()
			}
			if old.protected != nil {
				old.protected.Retire()
			}
			old.mu.Unlock()
		}
		target := vault.Target{Origin: prep.Origin, Account: prep.PreparationID}
		navigation := sha256.Sum256([]byte("manual-source\x00" + prep.PreparationID + "\x00" + first.DocumentID + "\x00" + first.ChromeStartToken))
		binding := vault.Binding{SessionID: in.SessionID, DocumentID: first.DocumentID, NavigationID: hex.EncodeToString(navigation[:]), Target: target}
		phase = "staging"
		protected, e := h.vaultExposure.BeginManualDOMTransition(working, binding, baseGuard)
		if e != nil {
			return e
		}
		// Retain every successfully created staging lease before selection or
		// qualification can refuse. Retirement inhibits it but does not release
		// the gate; later explicit Prepare must reach RecoverRetired with fresh
		// source-absence and durable CAS proof, including after a broker restart.
		item, e := h.credentials.retainManualStaging(p, prep, cb, binding, protected)
		if e != nil {
			protected.Retire()
			return e
		}
		successful := false
		defer func() {
			if !successful {
				protected.Retire()
				item.mu.Lock()
				item.state = "needsNativeAction"
				item.attention = manualPrivacyAttention(phase, e)
				item.mu.Unlock()
			}
		}()
		exposure.Store(&credentialExposure{lease: protected, binding: binding})
		phase = "selection"
		selected, revision, e := vault.ResolveOriginRecordDelivery(working, h.nativeVaultRecords, target, time.Now().Add(5*time.Minute), baseGuard)
		if e != nil || revision != prep.SelectedRevision {
			return errPrivateCredential
		}
		defer selected.Revoke()
		manager, e := vault.NewRecordDeliveryManager(selected, func(c context.Context, b vault.Binding) (vault.Binding, error) {
			if b != binding || protected.Verify(c, binding) != nil || baseGuard(c) != nil {
				return vault.Binding{}, errPrivateCredential
			}
			return binding, nil
		})
		if e != nil {
			return e
		}
		var proof chrome.CredentialPrivacyProof
		var authority chrome.ControlAuthority
		phase = "qualification"
		newBinding, newProtected, e := manualTransitionDOM(working, protected, binding, func(c context.Context) (vault.Binding, error) {
			var qualificationErr error
			e := selected.UseBinding(c, binding, func(ref vault.Reference, rev string) error {
				var e error
				proof, e = transition.Qualify(c, p, manager, binding, ref, rev)
				qualificationErr = e
				return e
			})
			if e != nil {
				if chrome.ManualCredentialPrivacyReason(qualificationErr) != "" {
					return vault.Binding{}, qualificationErr
				}
				return vault.Binding{}, e
			}
			phase = "transition"
			var valid bool
			authority, valid = proof.Authority()
			if !valid {
				return vault.Binding{}, errPrivateCredential
			}
			return vault.Binding{SessionID: in.SessionID, DocumentID: authority.Document.DocumentID, NavigationID: chrome.CredentialNavigationID(authority), Target: target}, nil
		})
		if e != nil {
			return e
		}
		// The parent remains held. Retire only known source input protection; original
		// outcomes/identities stay immutable, and no unknown business effect is cleared.
		protected = newProtected
		item.mu.Lock()
		item.protected, item.binding, item.authority = newProtected, newBinding, authority
		item.surface = model.Surface{Kind: "web", Origin: prep.Origin, TabID: authority.Document.QualifiedTabID()}
		item.publishExposure(false)
		item.mu.Unlock()
		exposure.Store(&credentialExposure{lease: newProtected, binding: newBinding, dom: true})
		guard := func(c context.Context) error {
			if baseGuard(c) != nil || newProtected.VerifyDOM(c, newBinding) != nil {
				return errPrivateCredential
			}
			return h.chrome.VerifyCredentialPrivacy(c, p, proof, model.Surface{Kind: "web", Origin: prep.Origin, TabID: authority.Document.QualifiedTabID()}, false)
		}
		phase = "cleanup"
		e = func() error {
			cleanupContext, stopCleanup := admission.cleanupContext(working)
			defer stopCleanup()
			return h.retireManualCredentialInputs(cleanupContext, p, prep, rows, guard)
		}()
		if e != nil {
			return e
		}
		item.mu.Lock()
		item.manualDOM, item.state, item.stage, item.attention = true, "privacyReady", "privacyReady", ""
		item.dom = &credentialDOMState{authority: authority, verify: func(c context.Context, actor auth.Principal, surface model.Surface, mutation bool) error {
			if item.done.Err() != nil || item.protected.VerifyDOM(c, item.binding) != nil {
				return errPrivateCredential
			}
			return h.chrome.VerifyCredentialPrivacy(c, actor, proof, surface, mutation)
		}}
		item.publishExposure(true)
		out = item.result()
		item.mu.Unlock()
		successful = true
		return nil
	})
	if e != nil {
		out.AttentionCode = manualPrivacyAttention(phase, e)
		return out, nil
	}
	return out, nil
}

// retainManualStaging stores only a host-owned volatile cleanup handle. It
// cannot publish DOM or input authority, and it never changes durable history.
func (s *credentialService) retainManualStaging(p auth.Principal, prep data.CredentialPreparationRecord, cb auth.ConsentBinding, binding vault.Binding, protected *vault.DeliveryLease) (*credentialSession, error) {
	if s == nil || s.done == nil || protected == nil || p.Validate() != nil || p.ClientID == "" || !p.HasScope("desktop:control") || prep.ProtectionState != "held" || prep.Revision != 1 || binding.Target.Validate() != nil || prep.Namespace != p.Namespace || prep.ClientID != p.ClientID || prep.PreparationID != binding.Target.Account || prep.Origin != binding.Target.Origin || cb.SessionID == "" || cb.SessionID != binding.SessionID || cb.GrantID == "" || cb.Purpose == "" {
		return nil, errPrivateCredential
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.done.Err() != nil {
		return nil, errPrivateCredential
	}
	if previous := s.pending[prep.PreparationID]; previous != nil && (previous.actor.Namespace != p.Namespace || previous.actor.ClientID != p.ClientID) {
		return nil, errPrivateCredential
	}
	lifetime, stop := context.WithCancel(s.done)
	item := &credentialSession{id: prep.PreparationID, done: lifetime, cancel: stop, actor: p, consent: cb, surface: model.Surface{Kind: "web", Origin: prep.Origin}, target: binding.Target, binding: binding, protected: protected, state: "needsNativeAction", attention: "manualPrivacyStagingUnavailable", expires: time.Now().Add(5 * time.Minute), revision: prep.SelectedRevision}
	item.publishExposure(false)
	s.pending[prep.PreparationID] = item
	return item, nil
}

func manualCredentialSource(p auth.Principal, prep data.CredentialPreparationRecord, rows []data.CredentialDeliveryRecord) (chrome.ManualCredentialSource, error) {
	if prep.Namespace != p.Namespace || prep.ClientID != p.ClientID || prep.ProtectionState != "held" || prep.Revision != 1 || len(rows) == 0 || len(rows) > 512 {
		return chrome.ManualCredentialSource{}, errPrivateCredential
	}
	first := rows[0]
	for _, r := range rows {
		if r.Namespace != p.Namespace || r.ClientID != p.ClientID || r.SessionID != prep.SessionID || r.GrantID != prep.GrantID || r.PurposeHash != prep.PurposeHash || r.SelectionID != prep.PreparationID || r.SelectedRevision != prep.SelectedRevision || r.Origin != prep.Origin || r.ChromeStartToken == "" || r.ChromeStartToken != first.ChromeStartToken || r.TabID <= 0 || r.TabID != first.TabID || r.DocumentID == "" || r.DocumentID != first.DocumentID || r.DocumentGeneration < 1 || r.ProfileChannel == "" || r.ProfileChannel != first.ProfileChannel || r.BrowserInstance == "" || r.BrowserInstance != first.BrowserInstance || r.DispatchState != "dispatched" || r.Revision < 2 || r.ProtectionState != "held" && r.ProtectionState != "closed" {
			return chrome.ManualCredentialSource{}, errPrivateCredential
		}
	}
	return chrome.ManualCredentialSource{Identity: chrome.Identity{ProfileChannel: first.ProfileChannel, BrowserInstance: first.BrowserInstance, TabID: first.TabID, FrameID: 0, DocumentID: first.DocumentID, Generation: uint64(first.DocumentGeneration)}, Origin: prep.Origin, ChromeBirth: first.ChromeStartToken}, nil
}

// retireManualCredentialInputs preserves the held parent and every original
// dispatch outcome. The guard is the independently committed DOM capability.
func (h *Host) retireManualCredentialInputs(working context.Context, p auth.Principal, prep data.CredentialPreparationRecord, rows []data.CredentialDeliveryRecord, guard func(context.Context) error) error {
	return retireManualCredentialInputs(working, p, prep, rows, guard, h.durable.FinishCredentialDelivery)
}

func retireManualCredentialInputs(working context.Context, p auth.Principal, prep data.CredentialPreparationRecord, rows []data.CredentialDeliveryRecord, guard func(context.Context) error, finish func(context.Context, auth.Principal) error) error {
	if guard == nil || finish == nil || guard(working) != nil {
		return errPrivateCredential
	}
	if _, e := manualCredentialSource(p, prep, rows); e != nil {
		return e
	}
	clean, stop, e := data.WithCredentialCleanupAuthority(working, prep, rows, guard)
	if e != nil {
		return e
	}
	defer stop()
	for _, r := range rows {
		if r.ProtectionState == "closed" {
			continue
		}
		next := r
		next.ProtectionState = "closed"
		next.Revision++
		next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		bound, revoke, e := data.WithCredentialDeliveryAuthority(clean, data.CredentialDeliveryAuthority{Before: &r, Record: next}, guard)
		if e != nil {
			return e
		}
		e = finish(bound, p)
		revoke()
		if e != nil {
			return e
		}
	}
	return guard(working)
}

func manualPrivacyAttention(phase string, err error) string {
	switch chrome.ManualCredentialPrivacyReason(err) {
	case "invalidRequest":
		return "manualPrivacyInvalidRequest"
	case "authorityChanged":
		return "manualPrivacyAuthorityChanged"
	case "expired":
		return "manualPrivacyExpired"
	case "busy":
		return "manualPrivacyBusy"
	case "unknownEffects":
		return "manualPrivacyUnknownEffects"
	case "lifecycleInhibited":
		return "manualPrivacyLifecycleInhibited"
	case "sourceTabPresent":
		return "manualPrivacySourceTabPresent"
	case "inventoryUnavailable":
		return "manualPrivacyInventoryUnavailable"
	case "candidateUnavailable":
		return "manualPrivacyCandidateUnavailable"
	case "candidateAmbiguous":
		return "manualPrivacyCandidateAmbiguous"
	case "candidateChanged":
		return "manualPrivacyCandidateChanged"
	case "documentNotReady":
		return "manualPrivacyDocumentNotReady"
	case "redactionUnavailable":
		return "manualPrivacyRedactionUnavailable"
	}
	switch phase {
	case "source":
		return "manualPrivacySourceUnavailable"
	case "consent":
		return "manualPrivacyConsentUnavailable"
	case "absence":
		return "manualPrivacyAbsenceUnavailable"
	case "staging":
		return "manualPrivacyStagingUnavailable"
	case "selection":
		return "manualPrivacySelectionUnavailable"
	case "qualification":
		return "manualPrivacyQualificationUnavailable"
	case "transition":
		return "manualPrivacyTransitionUnavailable"
	case "cleanup":
		return "manualPrivacyCleanupUnavailable"
	}
	return "postSubmitPrivacyUnavailable"
}

// Preserve the private resolver error only for the closed Host classification.
// Vault's general transition API intentionally hides resolver details.
func manualTransitionDOM(ctx context.Context, lease *vault.DeliveryLease, binding vault.Binding, resolve func(context.Context) (vault.Binding, error)) (vault.Binding, *vault.DeliveryLease, error) {
	var resolveErr error
	next, protected, err := lease.TransitionDOM(ctx, binding, func(c context.Context) (vault.Binding, error) {
		result, e := resolve(c)
		resolveErr = e
		return result, e
	})
	if err != nil && chrome.ManualCredentialPrivacyReason(resolveErr) != "" {
		return vault.Binding{}, nil, resolveErr
	}
	return next, protected, err
}

// The current registered consent lease covers only synchronous cleanup. Its
// context is canceled by grant revocation, expiry or application-policy changes.
// Later persistent DOM checks have no active cleanup marker and reauthorize.
type manualCleanupAdmissionKey struct{}
type manualCleanupAdmission struct {
	host      *Host
	actor     auth.Principal
	sessionID string
	surface   model.Surface
	binding   auth.ConsentBinding
	lease     *consent.Lease
	active    atomic.Bool
}

func (a *manualCleanupAdmission) cleanupContext(ctx context.Context) (context.Context, func()) {
	a.active.Store(true)
	return context.WithValue(ctx, manualCleanupAdmissionKey{}, a), func() { a.active.Store(false) }
}
func (a *manualCleanupAdmission) check(ctx context.Context) error {
	actual, e := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if a == nil || a.host == nil || e != nil || !ok || actual.Namespace != a.actor.Namespace || actual.ClientID != a.actor.ClientID || binding != a.binding || a.host.Runtime.CheckSession(ctx, a.actor, a.sessionID) != nil || ctx.Err() != nil {
		return errPrivateCredential
	}
	if marker := ctx.Value(manualCleanupAdmissionKey{}); marker != nil {
		if marker != a || !a.active.Load() || a.lease == nil || a.lease.Context.Err() != nil {
			return errPrivateCredential
		}
		return nil
	}
	approved, e := a.host.authorizeConsentOperation(consent.RequireReusableGrant(ctx), a.actor, a.surface, true, consent.Control)
	if e != nil {
		return e
	}
	approved.Release()
	return ctx.Err()
}
