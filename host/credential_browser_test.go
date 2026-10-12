package host

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
	"strings"
	"testing"
)

type credentialBrowserFixture struct {
	admissionTransform                    func(context.Context, chrome.ControlAuthority) (chrome.ControlAuthority, error)
	scopeCapture                          func(context.Context, chrome.ControlAuthority, string) (chrome.CredentialProtectionScope, error)
	submitUnknown                         bool
	host                                  *Host
	session                               *credentialSession
	t                                     *testing.T
	unknown                               bool
	unavailable                           bool
	privacyCandidate                      bool
	postStage                             string
	challenge                             bool
	privacyCalls                          int
	waitForClose                          chan struct{}
	scopeAbsent                           func(context.Context, chrome.CredentialProtectionScope) error
	scopeRetire                           func(context.Context, chrome.CredentialProtectionScope) error
	preflightIdle                         bool
	preflightChecks, preflightRetirements int
	scopeDisjoint                         func(context.Context, chrome.CredentialProtectionScope, model.Surface) error
	fills, submits                        int
	admissions, freshness                 int
	inspectionFailure                     string
}

func (f *credentialBrowserFixture) AdmitCredentialControl(ctx context.Context, p auth.Principal, s model.Surface, admit func(context.Context) error) (chrome.ControlAdmission, error) {
	f.admissions++
	if admit(ctx) != nil {
		f.t.Fatal("unprotected private probe")
	}
	if blocked, e := f.host.durable.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
		f.t.Fatal("probe preceded durable preparation", e)
	}
	if f.inspectionFailure != "" {
		return chrome.ControlAdmission{FailureStage: "inspection", FailureReason: f.inspectionFailure, CredentialStage: "challenge"}, errors.New("closed fixture inspection refusal")
	}
	if f.unavailable {
		return chrome.ControlAdmission{}, errors.New("synthetic unavailable private inspector")
	}
	a := chrome.ControlAuthority{Owner: p.Namespace, ClientID: p.ClientID, BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("d", 64), Document: chrome.Document{Identity: chrome.Identity{ProfileChannel: "profile", BrowserInstance: "browser", DocumentID: "username-document", TabID: 7, Generation: 1}, Origin: s.Origin}, Lease: chrome.Lease{ID: "lease", Generation: 1}}
	a.Evidence.ChromeParent.StartToken = "chrome-birth"
	a.Evidence.NativeHost.StartToken = "host-birth"
	if f.admissionTransform != nil {
		var err error
		a, err = f.admissionTransform(ctx, a)
		if err != nil {
			return chrome.ControlAdmission{}, err
		}
	}
	return chrome.ControlAdmission{Authority: a, Confirmed: true, Created: true, CredentialStage: "username"}, nil
}
func (f *credentialBrowserFixture) FreshCredentialBinding(ctx context.Context, _ auth.Principal, _ chrome.ControlAuthority, b vault.Binding, admit func(context.Context) error) (vault.Binding, error) {
	f.freshness++
	if admit(ctx) != nil {
		f.t.Fatal("freshness without protection")
	}
	return b, nil
}
func (f *credentialBrowserFixture) assertReserved(ctx context.Context, p auth.Principal, id string, admit func(context.Context) error) {
	f.t.Helper()
	if auth.NativeHuman(ctx) || admit(ctx) != nil {
		f.t.Fatal("native authority/unprotected dispatch")
	}
	if len(f.session.attempts) == 0 {
		f.t.Fatal("missing reservation")
	}
	row := f.session.attempts[len(f.session.attempts)-1]
	if row.AttemptID != id || row.DispatchState != "unknown" {
		f.t.Fatal("dispatch before unknown")
	}
	sealed, revoke, e := data.WithCredentialDeliveryAuthority(ctx, data.CredentialDeliveryAuthority{Record: row}, admit)
	if e != nil {
		f.t.Fatal(e)
	}
	defer revoke()
	actual, e := f.host.durable.ReadCredentialDelivery(sealed, p)
	if e != nil || actual != row {
		f.t.Fatal("dispatch before actual committed unknown readback", e)
	}
}
func (f *credentialBrowserFixture) DeliverVaultCredential(ctx context.Context, p auth.Principal, _ chrome.ControlAuthority, id string, m *vault.Manager, b vault.Binding, ref vault.Reference, revision string, admit func(context.Context) error) (chrome.CredentialDeliveryResult, error) {
	f.assertReserved(ctx, p, id, admit)
	e := m.ConsumeRevision(ctx, b, ref, revision, func(c vault.Credentials) error {
		return c.WithBytes(func(u, pw []byte) error {
			if string(u) != "username-secret-canary" || string(pw) != "password-secret-canary" {
				f.t.Fatal("wrong record delivered")
			}
			f.fills++
			return nil
		})
	})
	if e != nil {
		f.t.Fatal(e)
	}
	if f.waitForClose != nil {
		close(f.waitForClose)
		<-ctx.Done()
		return chrome.CredentialDeliveryResult{DispatchState: "unknown"}, ctx.Err()
	}
	if f.unknown {
		return chrome.CredentialDeliveryResult{DispatchState: "unknown"}, errors.New("private lost-reply canary")
	}
	return chrome.CredentialDeliveryResult{DispatchState: "dispatched"}, nil
}
func (f *credentialBrowserFixture) SubmitVaultCredential(ctx context.Context, p auth.Principal, _ chrome.ControlAuthority, fill, id string, admit func(context.Context) error) (chrome.CredentialDeliveryResult, error) {
	f.assertReserved(ctx, p, id, admit)
	if fill == "" || fill == id {
		f.t.Fatal("submit reused fill attempt")
	}
	f.submits++
	if f.submitUnknown {
		return chrome.CredentialDeliveryResult{DispatchState: "unknown"}, errors.New("fixture lost submit acknowledgement")
	}
	return chrome.CredentialDeliveryResult{DispatchState: "dispatched"}, nil
}
func (f *credentialBrowserFixture) AdvanceVaultCredential(ctx context.Context, _ auth.Principal, a chrome.ControlAuthority, _ string, admit func(context.Context) error) (chrome.CredentialAdvanceResult, error) {
	if admit(ctx) != nil {
		f.t.Fatal("unprotected advance")
	}
	if f.postStage == "controlDiagnostic" {
		return chrome.CredentialAdvanceResult{}, errors.Join(chrome.ErrCredentialAdvanceControl, errors.New("PRIVATE-CANARY"))
	}
	if f.postStage == "pending" {
		return chrome.CredentialAdvanceResult{Stage: "pending"}, chrome.ErrCredentialPostSubmitPending
	}
	if f.postStage == "rejected" {
		return chrome.CredentialAdvanceResult{Stage: "rejected"}, chrome.ErrCredentialLoginRejected
	}
	if f.challenge {
		return chrome.CredentialAdvanceResult{Stage: "challenge"}, chrome.ErrCredentialNativeChallenge
	}
	if f.privacyCandidate {
		return chrome.CredentialAdvanceResult{Stage: "privacyCandidate"}, chrome.ErrCredentialPrivacyCandidate
	}
	a.Document.DocumentID = "password-document"
	a.Document.Generation++
	a.Lease.ID = "next-lease"
	a.Lease.Generation++
	return chrome.CredentialAdvanceResult{Authority: a, Stage: "password"}, nil
}
func (f *credentialBrowserFixture) CancelVaultCredential(context.Context, auth.Principal, chrome.ControlAuthority) error {
	return nil
}

func (f *credentialBrowserFixture) QualifyCredentialPrivacy(context.Context, auth.Principal, chrome.ControlAuthority, string, func(context.Context) error) (chrome.CredentialPrivacyProof, error) {
	f.privacyCalls++
	if f.privacyCandidate {
		return chrome.CredentialPrivacyProof{}, nil
	}
	return chrome.CredentialPrivacyProof{}, errors.New("fixture has no production privacy proof")
}
func (f *credentialBrowserFixture) VerifyCredentialPrivacy(context.Context, auth.Principal, chrome.CredentialPrivacyProof, model.Surface, bool) error {
	return errors.New("fixture has no production privacy proof")
}

func (f *credentialBrowserFixture) CaptureCredentialProtectionScope(ctx context.Context, p auth.Principal, a chrome.ControlAuthority, id string) (chrome.CredentialProtectionScope, error) {
	if f.scopeCapture != nil {
		return f.scopeCapture(ctx, a, id)
	}
	return chrome.CredentialProtectionScope{PreparationID: id, Identity: a.Document.Identity, Origin: a.Document.Origin, LoginRouteSHA256: strings.Repeat("e", 64), ChromeStartToken: a.Evidence.ChromeParent.StartToken, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash}, nil
}
func (f *credentialBrowserFixture) VerifyProtectionDisjoint(ctx context.Context, p auth.Principal, s chrome.CredentialProtectionScope, target model.Surface) error {
	if f.scopeDisjoint != nil {
		return f.scopeDisjoint(ctx, s, target)
	}
	return errPrivateCredential
}
func (f *credentialBrowserFixture) VerifyCredentialScopeAbsent(ctx context.Context, p auth.Principal, s chrome.CredentialProtectionScope) error {
	if f.scopeAbsent != nil {
		return f.scopeAbsent(ctx, s)
	}
	return errPrivateCredential
}

func (f *credentialBrowserFixture) RetireAbsentCredentialScope(ctx context.Context, p auth.Principal, s chrome.CredentialProtectionScope) error {
	if f.scopeRetire != nil {
		return f.scopeRetire(ctx, s)
	}
	return f.VerifyCredentialScopeAbsent(ctx, p, s)
}

func (f *credentialBrowserFixture) VerifyCredentialPreflightIdle(ctx context.Context, p auth.Principal, id, origin string) error {
	f.preflightChecks++
	if !f.preflightIdle || ctx.Err() != nil || id != f.session.id || origin != f.session.target.Origin || f.fills != 0 || f.submits != 0 {
		return errPrivateCredential
	}
	return nil
}
func (f *credentialBrowserFixture) RetireCredentialPreflight(ctx context.Context, p auth.Principal, id, origin string) error {
	if e := f.VerifyCredentialPreflightIdle(ctx, p, id, origin); e != nil {
		return e
	}
	f.preflightRetirements++
	return nil
}
