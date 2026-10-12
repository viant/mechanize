package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

// The production composition always uses Host.chrome. The unexported interface
// permits deterministic transport fixtures while exercising real host, consent,
// RecordStore/Manager and durable components; it is never configurable by JSON.
type credentialBrowser interface {
	credentialScopeBrowser
	QualifyCredentialPrivacy(context.Context, auth.Principal, chrome.ControlAuthority, string, func(context.Context) error) (chrome.CredentialPrivacyProof, error)
	VerifyCredentialPrivacy(context.Context, auth.Principal, chrome.CredentialPrivacyProof, model.Surface, bool) error
	AdmitCredentialControl(context.Context, auth.Principal, model.Surface, func(context.Context) error) (chrome.ControlAdmission, error)
	FreshCredentialBinding(context.Context, auth.Principal, chrome.ControlAuthority, vault.Binding, func(context.Context) error) (vault.Binding, error)
	DeliverVaultCredential(context.Context, auth.Principal, chrome.ControlAuthority, string, *vault.Manager, vault.Binding, vault.Reference, string, func(context.Context) error) (chrome.CredentialDeliveryResult, error)
	SubmitVaultCredential(context.Context, auth.Principal, chrome.ControlAuthority, string, string, func(context.Context) error) (chrome.CredentialDeliveryResult, error)
	AdvanceVaultCredential(context.Context, auth.Principal, chrome.ControlAuthority, string, func(context.Context) error) (chrome.CredentialAdvanceResult, error)
	CancelVaultCredential(context.Context, auth.Principal, chrome.ControlAuthority) error
}

func (s *credentialService) browser() credentialBrowser {
	if s.browserFixture != nil {
		return s.browserFixture
	}
	return s.host.chrome
}
