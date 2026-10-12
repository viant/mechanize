package host

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
	"strings"
	"testing"
	"time"
)

// This fixture qualifies only host policy routing, not a production renderer.
// The production state constructor is supplied solely by the opaque backend proof.
func exerciseCredentialDOMPolicy(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput) {
	t.Helper()
	item := h.credentials.pending[ref.PreparationID]
	bound := auth.WithConsentBinding(ctx, item.consent)
	next := item.binding
	next.DocumentID = "history-document"
	next.NavigationID = strings.Repeat("e", 64)
	b, l, e := item.protected.TransitionDOM(bound, item.binding, func(context.Context) (vault.Binding, error) { return next, nil })
	if e != nil {
		t.Fatal(e)
	}
	authority := item.authority
	authority.Document.DocumentID = next.DocumentID
	authority.Document.Generation++
	authority.Lease.Generation++
	fresh := true
	checks := 0
	item.binding = b
	item.protected = l
	item.authority = authority
	item.publishExposure(true)
	item.state = "privacyReady"
	item.stage = "privacyReady"
	item.dom = &credentialDOMState{authority: authority, verify: func(c context.Context, actor auth.Principal, surface model.Surface, _ bool) error {
		checks++
		cb, ok := auth.ConsentBindingFromContext(c)
		if !fresh || actor.ClientID != p.ClientID || !ok || cb != item.consent || (surface.TabID != "" && surface.TabID != authority.Document.QualifiedTabID()) {
			return errors.New("private proof unavailable")
		}
		return h.credentials.proofAdmission(item)(c)
	}}
	surface := model.Surface{Kind: "web", Origin: authority.Document.Origin, TabID: authority.Document.QualifiedTabID()}
	for _, target := range []model.Surface{surface, {Kind: "web", Origin: surface.Origin}} {
		for _, mutation := range []bool{false, true} {
			mode := consent.Observe
			if mutation {
				mode = consent.Control
			}
			lease, e := h.AuthorizeOperation(bound, p, target, mutation, mode)
			if e != nil {
				t.Fatal("qualified ordinary DOM route unavailable", mutation, e)
			}
			lease.Release()
		}
	}
	if checks != 4 {
		t.Fatal("fresh private proof not checked per ordinary operation")
	}
	// A permanent grant may admit a different descriptive purpose, but the
	// private redactor proof retains the original complete consent binding.
	for _, mutation := range []bool{false, true} {
		changed := item.consent
		changed.Purpose = "PURPOSE-CANARY"
		mode := consent.Observe
		if mutation {
			mode = consent.Control
		}
		lease, err := h.AuthorizeOperation(auth.WithConsentBinding(ctx, changed), p, surface, mutation, mode)
		if lease != nil {
			lease.Release()
			t.Fatal("purpose mismatch granted exposure")
		}
		var reason *model.MechanizeError
		if !errors.As(err, &reason) || reason.Code != "credentialPurposeMismatch" || reason.Stage != "consent" || reason.DispatchState != "notDispatched" || reason.EffectState != "none" || strings.Contains(reason.Message, "CANARY") || strings.Contains(reason.Message, item.consent.Purpose) {
			t.Fatal("purpose-only refusal lost its closed diagnostic", err)
		}
		if checks != 4 {
			t.Fatal("purpose mismatch reached DOM proof/input")
		}
	}
	for _, kind := range []string{"actor", "session", "grant", "tab"} {
		changed, actor, target := item.consent, p, surface
		changed.Purpose = "PURPOSE-CANARY"
		switch kind {
		case "actor":
			actor.ClientID = "foreign-client"
		case "session":
			changed.SessionID = "foreign-session"
		case "grant":
			changed.GrantID = "foreign-grant"
		case "tab":
			target.TabID = "foreign-tab"
		}
		foreign := auth.WithConsentBinding(auth.WithPrincipal(ctx, actor), changed)
		lease, err := h.credentials.authorizeDOM(foreign, actor, target, false, consent.Observe)
		if lease != nil {
			lease.Release()
			t.Fatal("foreign binding granted exposure", kind)
		}
		if !errors.Is(err, vault.ErrDeliveryProtected) {
			t.Fatal("foreign binding disclosed purpose diagnostic", kind, err)
		}
		lease, err = h.AuthorizeOperation(foreign, actor, target, false, consent.Observe)
		if lease != nil {
			lease.Release()
			t.Fatal("foreign public route granted exposure", kind)
		}
		var reason *model.MechanizeError
		if err == nil || errors.As(err, &reason) && reason.Code == "credentialPurposeMismatch" {
			t.Fatal("foreign public route disclosed purpose diagnostic", kind)
		}
		if checks != 4 {
			t.Fatal("foreign binding reached DOM proof/input", kind)
		}
	}
	// Ordinary native metadata and screenshot access retain their normal
	// consent checks while credential delivery protects its exact web DOM.
	native := model.Surface{Kind: "native", BundleID: "fixture.app"}
	nativeLease, nativeErr := h.AuthorizeOperation(bound, p, native, false, consent.Observe)
	if nativeErr != nil || nativeLease == nil {
		t.Fatal("authorized native observation blocked by browser DOM protection", nativeErr)
	}
	nativeLease.Release()
	if checks != 4 {
		t.Fatal("native observation entered private DOM proof")
	}
	for _, blocked := range []struct {
		surface model.Surface
		mode    consent.Mode
	}{{surface, consent.Record}, {model.Surface{Kind: "web", Origin: surface.Origin, TabID: "different-tab"}, consent.Observe}, {model.Surface{Kind: "web", Origin: "https://foreign.invalid", TabID: surface.TabID}, consent.Control}} {
		if lease, e := h.AuthorizeOperation(bound, p, blocked.surface, false, blocked.mode); e == nil {
			lease.Release()
			t.Fatal("privacy broadened beyond exact DOM", blocked)
		}
	}
	if _, e = h.vaultExposure.AcquireExposure(); !errors.Is(e, vault.ErrDeliveryProtected) {
		t.Fatal("DOM permit released desktop exposure")
	}
	status, e := h.CredentialStatus(ctx, p, ref)
	if e != nil || status.State != "privacyReady" || status.Surface == nil || *status.Surface != surface {
		t.Fatal("opaque status lost qualified routing", status, e)
	}
	item.uncertain = true
	if lease, e := h.AuthorizeOperation(bound, p, surface, false, consent.Observe); e == nil {
		lease.Release()
		t.Fatal("unknown attempt bypassed privacy barrier")
	}
	item.uncertain = false
	fresh = false
	if lease, e := h.AuthorizeOperation(bound, p, surface, false, consent.Observe); e == nil {
		lease.Release()
		t.Fatal("stale/changed document proof reused")
	}
	status, e = h.CredentialStatus(ctx, p, ref)
	if e != nil || status.State != "needsNativeAction" || status.AttentionCode != "postLoginDocumentUnavailable" || status.Surface != nil {
		t.Fatal("stale post-login state still advertised readiness", status, e)
	}
	fresh = true
	status, e = h.CredentialStatus(ctx, p, ref)
	if e != nil || status.State != "privacyReady" || status.AttentionCode != "" {
		t.Fatal("fresh independent qualification did not restore readiness", status, e)
	}
	lease, e := h.AuthorizeOperation(bound, p, surface, true, consent.Control)
	if e != nil {
		t.Fatal(e)
	}
	item.cancel()
	select {
	case <-lease.Context.Done():
	case <-time.After(time.Second):
		t.Fatal("native cancellation did not cancel DOM lease")
	}
	lease.Release()
	if blocked, e := h.durable.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
		t.Fatal("privacy transition changed durable unknown/protection ledger")
	}
}

func TestCredentialPrivacyProductionConstructorCannotUseCallerProof(t *testing.T) {
	// A zero/JSON stage cannot construct the opaque backend proof. Missing exact
	// committed attempts remains unavailable even with a synthetic state string.
	s := newCredentialService(&Host{})
	defer s.close()
	item := &credentialSession{state: "privacyReady", stage: "privacyReady", dispatch: "dispatched", submitAttempt: strings.Repeat("a", 64)}
	if s.qualifyDOM(context.Background(), auth.Principal{}, item) == nil || item.dom != nil {
		t.Fatal("caller stage enabled ordinary routing")
	}
}

func TestCredentialPrivacyAttentionAllowsOnlyClosedQualificationPhases(t *testing.T) {
	if !closedCredentialPrivacyAttention("postSubmitPrivacyNotReady") {
		t.Fatal("closed authenticated not-ready diagnostic rejected")
	}
	for _, phase := range []string{"Admission", "Fence", "Reply", "Commit", "Probe", "Promotion"} {
		if !closedCredentialPrivacyAttention("postSubmitPrivacy" + phase + "Unavailable") {
			t.Fatal("closed phase rejected", phase)
		}
	}
	for _, code := range []string{"postSubmitPrivacyNotReady PRIVATE_CANARY", "postSubmitPrivacyPRIVATE_CANARY", "postSubmitPrivacyAdmissionUnavailable extra", "PRIVATE_CANARY", ""} {
		if closedCredentialPrivacyAttention(code) {
			t.Fatal("untrusted attention accepted")
		}
	}
}
