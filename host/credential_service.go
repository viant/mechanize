package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

var errPrivateCredential = errors.New("private credential operation unavailable")
var errCredentialCandidatePending = errors.New("private credential candidate pending")

type credentialService struct {
	mu             sync.Mutex
	host           *Host
	browserFixture credentialBrowser
	pending        map[string]*credentialSession
	closed         bool
	done           context.Context
	cancel         context.CancelFunc
}
type credentialSession struct {
	manualDOM                  bool
	mu                         sync.Mutex
	id                         string
	done                       context.Context
	cancel                     context.CancelFunc
	actor                      auth.Principal
	consent                    auth.ConsentBinding
	surface                    model.Surface
	target                     vault.Target
	expires                    time.Time
	state, stage, dispatch     string
	attention                  string
	selection                  *vault.RecordDelivery
	revision                   string
	preparation                *vault.DeliveryPreparation
	protected                  *vault.DeliveryLease
	binding                    vault.Binding
	authority                  chrome.ControlAuthority
	protectionScope            chrome.CredentialProtectionScope
	dom                        *credentialDOMState
	exposure                   atomic.Pointer[credentialExposure]
	fillAttempt, submitAttempt string
	uncertain                  bool
	preflightNoInput           bool
	attempts                   []data.CredentialDeliveryRecord
}
type nativeCredentialPending struct {
	ID        string `json:"id"`
	Origin    string `json:"origin"`
	ClientID  string `json:"clientId"`
	Purpose   string `json:"purpose"`
	ExpiresAt string `json:"expiresAt"`
}

func credentialID() string {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
func newCredentialService(h *Host) *credentialService {
	ctx, cancel := context.WithCancel(context.Background())
	return &credentialService{host: h, pending: map[string]*credentialSession{}, done: ctx, cancel: cancel}
}
func (s *credentialService) available() bool {
	return s != nil && s.host != nil && s.host.nativeVaultRecords != nil && s.host.vaultExposure != nil && s.host.chrome != nil && s.host.durable != nil && s.host.Runtime != nil
}
func (s *credentialSession) result() gateway.CredentialResult {
	r := gateway.CredentialResult{PreparationID: s.id, State: s.state, Stage: s.stage, DispatchState: s.dispatch}
	if s.state == "needsNativeAction" || s.state == "unknown" || s.state == "awaitingPreflight" || s.state == "submitted" {
		r.AttentionCode = s.attention
	}
	if s.state == "privacyReady" && s.dom != nil {
		r.Surface = &model.Surface{Kind: "web", Origin: s.dom.authority.Document.Origin, TabID: s.dom.authority.Document.QualifiedTabID()}
	}
	return r
}
func (s *credentialService) check(ctx context.Context, p auth.Principal, sessionID string) error {
	actual, e := auth.FromContext(ctx)
	if !s.available() || e != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || p.ClientID == "" || !p.HasScope("desktop:control") || auth.NativeHuman(ctx) || s.host.Runtime.CheckSession(ctx, p, sessionID) != nil {
		return errPrivateCredential
	}
	return nil
}
func (s *credentialService) prepare(ctx context.Context, p auth.Principal, in gateway.CredentialPrepareInput) (gateway.CredentialResult, error) {
	if s.check(ctx, p, in.SessionID) != nil || in.Surface.Kind != "web" || in.Surface.ProcessID != 0 || in.Surface.ProcessStartToken != "" || in.Surface.BundleID != "" || in.Surface.Title != "" || len(in.Purpose) == 0 || len(in.Purpose) > 512 {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	id := credentialID()
	target := vault.Target{Origin: in.Surface.Origin, Account: id}
	if id == "" || target.Validate() != nil {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: in.SessionID, GrantID: in.GrantID, Purpose: in.Purpose})
	// Authenticate the explicit login request before a bounded cleanup can
	// return a diagnostic or retire any old source. This metadata consent lease
	// does not admit content exposure or credential consumption.
	preparationConsent, e := s.host.authorizeConsentOperation(consent.RequireReusableGrant(ctx), p, in.Surface, true, consent.Control)
	if e != nil {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	defer preparationConsent.Release()
	ctx = preparationConsent.Context
	if e := s.retireAbsentCredentialSources(ctx, p, in.Surface.Origin); e != nil {
		return gateway.CredentialResult{State: "needsNativeAction", AttentionCode: credentialScopePreparationReason(e)}, nil
	}
	lease, e := s.host.AuthorizeOperation(consent.RequireReusableGrant(ctx), p, in.Surface, true, consent.Control)
	if e != nil {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	defer lease.Release()
	binding, ok := auth.ConsentBindingFromContext(lease.Context)
	if !ok || binding.GrantID == "" {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	flowContext, flowCancel := context.WithCancel(s.done)
	item := &credentialSession{id: id, done: flowContext, cancel: flowCancel, actor: p, consent: binding, surface: in.Surface, target: target, expires: time.Now().Add(5 * time.Minute), state: "awaitingPreflight"}
	// Reusable control consent authorizes private origin matching; secret creation
	// and editing still belong to native administration. Never forge NativeHuman.
	authorize := func(c context.Context) error {
		if s.host.Runtime.CheckSession(c, p, in.SessionID) != nil {
			return errPrivateCredential
		}
		verified, err := s.host.authorizeConsentOperation(consent.RequireReusableGrant(c), p, in.Surface, true, consent.Control)
		if err != nil {
			return errPrivateCredential
		}
		defer verified.Release()
		return c.Err()
	}
	selected, revision, resolveErr := vault.ResolveOriginRecordDelivery(lease.Context, s.host.nativeVaultRecords, target, item.expires, authorize)
	if resolveErr != nil && !errors.Is(resolveErr, vault.ErrCredentialConfiguration) {
		flowCancel()
		return gateway.CredentialResult{}, errPrivateCredential
	}
	item.selection, item.revision = selected, revision
	if resolveErr != nil {
		item.state = "needsConfiguration"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Only preparations with no protection or attempted effect may be retired.
	// Expiry cannot erase an unknown effect or its durable privacy barrier.
	for oldID, old := range s.pending {
		old.mu.Lock()
		retire := (!time.Now().Before(old.expires) || old.state == "needsConfiguration") && old.preparation == nil && old.protected == nil && old.dom == nil && len(old.attempts) == 0 && old.fillAttempt == "" && old.submitAttempt == "" && !old.uncertain && old.dispatch != "unknown"
		if retire {
			if old.selection != nil {
				old.selection.Revoke()
			}
			if old.cancel != nil {
				old.cancel()
			}
			delete(s.pending, oldID)
		}
		old.mu.Unlock()
	}
	if s.closed || lease.Context.Err() != nil || flowContext.Err() != nil || len(s.pending) >= 128 {
		flowCancel()
		if selected != nil {
			selected.Revoke()
		}
		return gateway.CredentialResult{}, errPrivateCredential
	}
	for _, old := range s.pending {
		if old.actor.Namespace == p.Namespace && old.actor.ClientID == p.ClientID && old.consent.SessionID == in.SessionID {
			flowCancel()
			if selected != nil {
				selected.Revoke()
			}
			return gateway.CredentialResult{}, errPrivateCredential
		}
	}
	s.pending[id] = item
	return item.result(), nil
}
func (s *credentialService) lookup(ctx context.Context, p auth.Principal, in gateway.CredentialRefInput) (*credentialSession, error) {
	if s.check(ctx, p, in.SessionID) != nil {
		return nil, errPrivateCredential
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.pending[in.PreparationID]
	if s.closed || item == nil || item.actor.Namespace != p.Namespace || item.actor.ClientID != p.ClientID || item.consent.SessionID != in.SessionID {
		return nil, errPrivateCredential
	}
	return item, nil
}
func (s *credentialService) native(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	p, e := auth.FromContext(ctx)
	if !s.available() || e != nil || !auth.NativeHuman(ctx) || !p.HasScope("consent:admin") {
		return nil, errPrivateCredential
	}
	var in struct {
		SessionID string `json:"sessionID"`
		ID        string `json:"id,omitempty"`
		RecordID  string `json:"recordId,omitempty"`
		Revision  string `json:"revision,omitempty"`
	}
	if decodeNativeCredential(raw, &in) != nil || in.SessionID == "" {
		return nil, errPrivateCredential
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errPrivateCredential
	}
	items := make([]*credentialSession, 0, len(s.pending))
	for _, v := range s.pending {
		if v.actor.Namespace == p.Namespace {
			items = append(items, v)
		}
	}
	s.mu.Unlock()
	if method == "credential.pending" {
		if in.ID != "" || in.RecordID != "" || in.Revision != "" {
			return nil, errPrivateCredential
		}
		out := []nativeCredentialPending{}
		return out, nil
	}
	if method != "credential.cancel" {
		return nil, errPrivateCredential
	}
	var item *credentialSession
	for _, v := range items {
		if v.id == in.ID {
			item = v
		}
	}
	if item == nil {
		return nil, errPrivateCredential
	}
	if method == "credential.cancel" {
		if in.RecordID != "" || in.Revision != "" {
			return nil, errPrivateCredential
		}
		if item.cancel != nil {
			item.cancel()
		}
		item.mu.Lock()
		if item.selection != nil {
			item.selection.Revoke()
		}
		if item.protected != nil {
			item.protected.Retire()
		}
		if item.preparation != nil {
			item.preparation.Retire()
		}
		if item.authority.Document.DocumentID != "" {
			s.browser().CancelVaultCredential(auth.WithPrincipal(context.Background(), item.actor), item.actor, item.authority)
		}
		item.state = "needsNativeAction"
		removable := item.preparation == nil && item.protected == nil && len(item.attempts) == 0
		item.mu.Unlock()
		if removable {
			s.mu.Lock()
			if s.pending[item.id] == item {
				delete(s.pending, item.id)
			}
			s.mu.Unlock()
		}
		return struct {
			Accepted bool `json:"accepted"`
		}{true}, nil
	}
	return nil, errPrivateCredential
}
func decodeNativeCredential(raw []byte, v any) error { return decodeClosedCredential(raw, v) }

func (s *credentialService) operation(ctx context.Context, p auth.Principal, in gateway.CredentialRefInput, kind string) (gateway.CredentialResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if s != nil && s.done != nil {
		stop := context.AfterFunc(s.done, cancel)
		defer stop()
	}
	item, e := s.lookup(ctx, p, in)
	if e != nil {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	if item.done != nil {
		stop := context.AfterFunc(item.done, cancel)
		defer stop()
	}
	ctx = auth.WithConsentBinding(ctx, item.consent)
	var out gateway.CredentialResult
	entered := false
	e = s.host.durable.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) (operationErr error) {
		item.mu.Lock()
		defer item.mu.Unlock()
		entered = true
		defer func() {
			if operationErr != nil || ctx.Err() != nil || item.done != nil && item.done.Err() != nil {
				if errors.Is(operationErr, errCredentialCandidatePending) && ctx.Err() == nil && item.preparation == nil {
					item.state = "awaitingPreflight"
				} else if item.dispatch == "unknown" {
					item.state = "unknown"
				} else {
					item.state = "needsNativeAction"
				}
			}
			out = item.result()
		}()
		if item.state == "needsConfiguration" {
			return nil
		}
		if kind == "status" && item.submitAttempt == "" && item.state != "awaitingPreflight" && item.state != "ready" && time.Now().Before(item.expires) {
			return nil
		}
		if item.dom == nil && (item.selection == nil || !time.Now().Before(item.expires)) && !(kind == "status" && item.metadataContinuation()) {
			// Expiry already forbids all value consumption. Retain metadata-only
			// provenance so a known submit can still finish privacy qualification.
			item.state = "needsNativeAction"
			return nil
		}
		if kind == "apply" && item.state != "ready" || kind == "submit" && (item.state != "filled" || item.submitAttempt != "") {
			return nil
		}
		lease, e := s.host.authorizeConsentOperation(held, p, item.surface, true, consent.Control)
		if e != nil {
			return errPrivateCredential
		}
		defer lease.Release()
		held = lease.Context
		admit := func(c context.Context) error {
			if c.Err() != nil || item.dom == nil && !item.metadataContinuation() && !time.Now().Before(item.expires) || s.host.Runtime.CheckSession(c, p, item.consent.SessionID) != nil {
				return errPrivateCredential
			}
			return nil
		}
		if kind == "status" {
			if item.dom != nil {
				return s.verifyDOMStatus(held, p, item)
			}
			if item.state == "awaitingPreflight" && item.protected == nil {
				if e = s.pin(held, p, item, admit); e != nil {
					return e
				}
				item.state = "ready"
				return nil
			}
			if item.state == "ready" && item.protected != nil && item.fillAttempt == "" {
				guard := func(c context.Context) error {
					if admit(c) != nil || item.selection.Verify(c, item.binding) != nil {
						return errPrivateCredential
					}
					return item.protected.Verify(c, item.binding)
				}
				actual, e := s.browser().FreshCredentialBinding(held, p, item.authority, item.binding, guard)
				if e != nil || actual != item.binding {
					return errPrivateCredential
				}
				return nil
			}
			return s.advance(held, p, item, admit)
		}
		if item.protected == nil {
			return errPrivateCredential
		}
		guard := func(c context.Context) error {
			if admit(c) != nil || item.protected.Verify(c, item.binding) != nil || item.selection.Verify(c, item.binding) != nil {
				return errPrivateCredential
			}
			return nil
		}
		action := func() error { return s.dispatch(held, p, item, kind, guard) }
		if kind == "apply" {
			return item.protected.WithDelivery(held, item.binding, action)
		}
		return item.protected.WithSubmit(held, item.binding, action)
	})
	if !entered || e != nil && out.PreparationID == "" {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	if kind == "status" {
		// Retire only after leaving the generated invocation and item locks.
		// Pending/unknown inspections lack the local no-input proof and remain held.
		item.mu.Lock()
		rejected := item.preflightNoInput
		item.mu.Unlock()
		if rejected {
			if e := s.releaseRejectedPreflight(ctx, p, item); e != nil {
				out.PreflightRelease = "unconfirmed"
			} else {
				out.PreflightRelease = "released"
			}
		}
	}
	return out, nil
}
func (s *credentialService) pin(ctx context.Context, p auth.Principal, item *credentialSession, admit func(context.Context) error) error {
	item.attention = "preparationBarrier"
	blocked, e := s.host.durable.CredentialDeliveryBlocked(ctx, p)
	if e != nil || blocked {
		return errPrivateCredential
	}
	item.attention = "privateBrowserAdmission"
	if probe, ok := s.browser().(interface {
		CredentialCandidateAvailable(context.Context, auth.Principal, model.Surface) error
	}); ok {
		if cause := probe.CredentialCandidateAvailable(ctx, p, item.surface); cause != nil {
			switch {
			case errors.Is(cause, chrome.ErrCredentialCandidateUnavailable):
				item.attention = "privateCandidateUnavailable"
			case errors.Is(cause, chrome.ErrCredentialCandidateAmbiguous):
				item.attention = "privateCandidateAmbiguous"
			case errors.Is(cause, chrome.ErrCredentialChannelBusy):
				item.attention = "privateChannelBusy"
			}
			return errCredentialCandidatePending
		}
	}
	item.attention = "entryProtection"
	prep, e := s.host.vaultExposure.BeginDeliveryPreparation(ctx, item.target, admit, func(context.Context) error { return vault.ErrEntryCleanup })
	if e != nil {
		return errPrivateCredential
	}
	item.preparation = prep
	item.state = "protected"
	r := data.CredentialPreparationRecord{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: item.consent.SessionID, PreparationID: item.id, GrantID: item.consent.GrantID, PurposeHash: data.CredentialDeliveryPurposeHash(item.consent.Purpose), Origin: item.target.Origin, SelectedRevision: item.revision, ProtectionState: "held", Revision: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	guard := func(c context.Context) error {
		if admit(c) != nil {
			return errPrivateCredential
		}
		return prep.Verify(c, item.target)
	}
	item.attention = "preparationAuthority"
	sealed, revoke, e := data.WithCredentialPreparationAuthority(ctx, r, guard)
	if e != nil {
		return errPrivateCredential
	}
	defer revoke()
	item.attention = "preparationReservation"
	if s.host.durable.ReserveCredentialPreparation(sealed, p) != nil {
		return errPrivateCredential
	}
	item.attention = "privateBrowserAdmission"
	binding, protected, e := prep.Pin(ctx, func(c context.Context) (vault.Binding, error) {
		a, e := s.browser().AdmitCredentialControl(c, p, item.surface, guard)
		if e != nil || !a.Confirmed {
			item.preflightNoInput = a.PreflightNoInput && !a.Created && !a.Confirmed
			// Exact local phases only: no provider error or renderer detail can
			// become an automation-visible diagnostic.
			switch a.FailureStage {
			case "candidate":
				item.attention = "privateCandidateUnavailable"
			case "authority":
				item.attention = "privateAuthorityUnavailable"
			case "inspection":
				switch a.CredentialStage {
				case "username", "password", "pair", "challenge", "unavailable", "pending", "rejected":
					item.stage = a.CredentialStage
				}
				item.attention = chrome.CredentialInspectionAttention(a.FailureReason)
			case "acquisition":
				item.attention = "privateLeaseUnavailable"
			}
			return vault.Binding{}, errPrivateCredential
		}
		item.authority = a.Authority
		item.attention = "sourceScopePersistence"
		if e = s.captureProtectionScope(sealed, p, item, a.Authority); e != nil {
			return vault.Binding{}, e
		}
		item.stage = a.CredentialStage
		return vault.Binding{SessionID: item.consent.SessionID, DocumentID: a.Authority.Document.DocumentID, NavigationID: chrome.CredentialNavigationID(a.Authority), Target: item.target}, nil
	})
	if e != nil {
		return errPrivateCredential
	}
	item.binding = binding
	item.protected = protected
	item.publishExposure(false)
	item.attention = ""
	return nil
}
func (s *credentialService) dispatch(ctx context.Context, p auth.Principal, item *credentialSession, kind string, guard func(context.Context) error) error {
	id := credentialID()
	if id == "" {
		return errPrivateCredential
	}
	a := item.authority
	now := time.Now().UTC().Format(time.RFC3339Nano)
	r := data.CredentialDeliveryRecord{PurposeHash: data.CredentialDeliveryPurposeHash(item.consent.Purpose), SelectedRevision: item.revision, Namespace: p.Namespace, ClientID: p.ClientID, SessionID: item.consent.SessionID, AttemptID: id, SelectionID: item.id, GrantID: item.consent.GrantID, Origin: item.target.Origin, ProfileChannel: a.Document.ProfileChannel, BrowserInstance: a.Document.BrowserInstance, DocumentID: a.Document.DocumentID, DocumentGeneration: int(a.Document.Generation), TabID: a.Document.TabID, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash, RendererLeaseID: a.Lease.ID, RendererLeaseGeneration: int(a.Lease.Generation), ChromeStartToken: a.Evidence.ChromeParent.StartToken, NativeHostStartToken: a.Evidence.NativeHost.StartToken, DispatchState: "unknown", ProtectionState: "held", Revision: 1, CreatedAt: now, UpdatedAt: now}
	sealed, revoke, e := data.WithCredentialDeliveryAuthority(ctx, data.CredentialDeliveryAuthority{Record: r}, guard)
	if e != nil {
		return errPrivateCredential
	}
	defer revoke()
	// Consume before reserve: an uncertain commit also forbids replay.
	previousUncertain := item.uncertain
	item.uncertain = true
	item.dispatch = "unknown"
	item.state = "unknown"
	if kind == "apply" {
		item.fillAttempt = id
	} else {
		item.submitAttempt = id
	}
	item.attempts = append(item.attempts, r)
	attemptIndex := len(item.attempts) - 1
	if s.host.durable.ReserveCredentialDelivery(sealed, p) != nil {
		return errPrivateCredential
	}
	result := chrome.CredentialDeliveryResult{DispatchState: "unknown"}
	if kind == "submit" {
		result, e = s.browser().SubmitVaultCredential(ctx, p, a, item.fillAttempt, id, guard)
	} else {
		manager, me := vault.NewRecordDeliveryManager(item.selection, func(c context.Context, b vault.Binding) (vault.Binding, error) {
			if guard(c) != nil {
				return vault.Binding{}, errPrivateCredential
			}
			return s.browser().FreshCredentialBinding(c, p, a, b, guard)
		})
		if me != nil {
			return errPrivateCredential
		}
		e = item.selection.UseBinding(ctx, item.binding, func(ref vault.Reference, revision string) error {
			var de error
			result, de = s.browser().DeliverVaultCredential(ctx, p, a, id, manager, item.binding, ref, revision, guard)
			return de
		})
	}
	// A provider error cannot become a diagnostic or prove no dispatch.
	if e != nil && result.DispatchState != "notDispatched" {
		result.DispatchState = "unknown"
	}
	if result.DispatchState != "dispatched" && result.DispatchState != "notDispatched" {
		result.DispatchState = "unknown"
	}
	after := r
	after.DispatchState = result.DispatchState
	after.Revision = 2
	after.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	finished, finishRevoke, fe := data.WithCredentialDeliveryAuthority(ctx, data.CredentialDeliveryAuthority{Before: &r, Record: after}, guard)
	if fe != nil {
		return errPrivateCredential
	}
	defer finishRevoke()
	if s.host.durable.FinishCredentialDelivery(finished, p) != nil {
		return errPrivateCredential
	}
	item.attempts[attemptIndex] = after
	if result.DispatchState != "unknown" {
		item.uncertain = previousUncertain
	}
	item.dispatch = result.DispatchState
	// Only host-defined phases leave this private lane. Provider errors and
	// credential values must never become diagnostics.
	if result.DispatchState != "dispatched" {
		switch result.FailureStage {
		case "deliveryAdmission", "privateBindingFresh", "localVaultRead", "deliveryLane", "deliveryAuthority", "deliveryEncoding", "deliveryTransport", "privateFormReply":
			item.attention = result.FailureStage
		}
	}
	switch result.DispatchState {
	case "dispatched":
		if kind == "submit" {
			item.state = "submitted"
		} else {
			item.state = "filled"
		}
	case "notDispatched":
		item.state = "needsNativeAction"
	default:
		item.state = "unknown"
	}
	item.publishExposure(false)
	return nil
}
func (s *credentialService) advance(ctx context.Context, p auth.Principal, item *credentialSession, admit func(context.Context) error) error {
	if item.protected == nil || item.submitAttempt == "" {
		return nil
	}
	guard := func(c context.Context) error {
		if admit(c) != nil {
			return errPrivateCredential
		}
		return item.protected.Verify(c, item.binding)
	}
	privacyCandidate := false
	postStage := ""
	postAttention := "postSubmitAdvanceUnavailable"
	var next chrome.ControlAuthority
	b, l, e := item.protected.AdvancePrivate(ctx, item.binding, func(c context.Context) (vault.Binding, error) {
		r, e := s.browser().AdvanceVaultCredential(c, p, item.authority, item.submitAttempt, guard)
		if e != nil {
			postAttention = chrome.CredentialAdvanceAttention(e)
		}
		if errors.Is(e, chrome.ErrCredentialPostSubmitPending) {
			postStage = "pending"
		}
		if errors.Is(e, chrome.ErrCredentialLoginRejected) {
			postStage = "rejected"
		}
		if errors.Is(e, chrome.ErrCredentialNativeChallenge) {
			item.stage = "challenge"
			item.state = "needsNativeAction"
		}
		if errors.Is(e, chrome.ErrCredentialPrivacyCandidate) {
			privacyCandidate = true
		}
		if e != nil {
			return vault.Binding{}, errPrivateCredential
		}
		next = r.Authority
		item.stage = r.Stage
		return vault.Binding{SessionID: item.consent.SessionID, DocumentID: next.Document.DocumentID, NavigationID: chrome.CredentialNavigationID(next), Target: item.target}, nil
	})
	if e != nil {
		if postStage != "" {
			item.stage = postStage
			if postStage == "pending" {
				item.state = "submitted"
				item.attention = "postSubmitPending"
			} else {
				item.state = "needsNativeAction"
				item.attention = "loginRejected"
			}
			return nil
		}
		if privacyCandidate {
			if err := s.qualifyDOM(ctx, p, item); err != nil {
				if !closedCredentialPrivacyAttention(item.attention) {
					item.attention = "postSubmitPrivacyUnavailable"
				}
				return err
			}
			return nil
		}
		// Closed stage codes distinguish private transport from redactor
		// qualification; provider errors and page contents remain withheld.
		item.attention = postAttention
		return e
	}
	item.authority = next
	item.binding = b
	item.protected = l
	item.fillAttempt = ""
	item.submitAttempt = ""
	item.dispatch = ""
	item.state = "ready"
	item.publishExposure(false)
	if !time.Now().Before(item.expires) {
		item.state = "needsNativeAction"
	}
	return nil
}
func (s *credentialService) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	items := make([]*credentialSession, 0, len(s.pending))
	for _, i := range s.pending {
		items = append(items, i)
	}
	s.mu.Unlock()
	for _, i := range items {
		i.mu.Lock()
		if i.selection != nil {
			i.selection.Revoke()
		}
		if i.protected != nil {
			if s.host.chrome != nil {
				s.browser().CancelVaultCredential(auth.WithPrincipal(context.Background(), i.actor), i.actor, i.authority)
			}
			i.protected.Retire()
		}
		if i.preparation != nil {
			i.preparation.Retire()
		}
		i.mu.Unlock()
	}
}
func (h *Host) CredentialPrepare(c context.Context, p auth.Principal, in gateway.CredentialPrepareInput) (gateway.CredentialResult, error) {
	if h == nil || h.credentials == nil {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	return h.credentials.prepare(c, p, in)
}
func (h *Host) CredentialApply(c context.Context, p auth.Principal, in gateway.CredentialRefInput) (gateway.CredentialResult, error) {
	if h == nil || h.credentials == nil {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	return h.credentials.operation(c, p, in, "apply")
}
func (h *Host) CredentialSubmit(c context.Context, p auth.Principal, in gateway.CredentialRefInput) (gateway.CredentialResult, error) {
	if h == nil || h.credentials == nil {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	return h.credentials.operation(c, p, in, "submit")
}
func (h *Host) CredentialStatus(c context.Context, p auth.Principal, in gateway.CredentialRefInput) (gateway.CredentialResult, error) {
	if h == nil || h.credentials == nil {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	h.credentials.mu.Lock()
	item := h.credentials.pending[in.PreparationID]
	h.credentials.mu.Unlock()
	manual := false
	if item != nil {
		item.mu.Lock()
		manual = item.manualDOM
		item.mu.Unlock()
	}
	result, e := h.credentials.operation(c, p, in, "status")
	if manual && e == nil && result.State == "needsNativeAction" && result.AttentionCode == "postLoginDocumentUnavailable" {
		return h.CredentialResumeManual(c, p, in)
	}
	return result, e
}

func (item *credentialSession) metadataContinuation() bool {
	return item != nil && item.submitAttempt != "" && item.dispatch == "dispatched" && !item.uncertain
}
