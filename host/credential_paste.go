package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
	"strings"
)

// CredentialPasteOptions is trusted host enrollment, never tool input. Target
// resolves the exact private password recipient without input. Its adapter must
// retain process/document/focus authority at every probe/paste boundary, and must
// preserve the original attempt's private fill receipt for separate submission.
// Clipboard is a trusted factory (nil selects the local platform driver).
// The packaged host deliberately has no default recipient provider yet.
type CredentialPasteOptions struct {
	Target    func(context.Context, auth.Principal, model.Surface, chrome.ControlAuthority, vault.Binding, string, func(context.Context) error) (vault.PasswordPasteTarget, error)
	Clipboard func() vault.PasswordPasteClipboard
}

// CredentialPaste uses exactly the same owned preparation and durable fill slot
// as CredentialApply. Unsupported fallback neither consumes nor poisons a ready
// DOM preparation. It accepts no value, clipboard text, field selector or key.
func (h *Host) CredentialPaste(ctx context.Context, p auth.Principal, in gateway.CredentialRefInput) (gateway.CredentialResult, error) {
	if h == nil || h.credentials == nil || strings.HasPrefix(p.ClientID, "controller:") {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	item, err := h.credentials.lookup(ctx, p, in)
	if err != nil {
		return gateway.CredentialResult{}, errPrivateCredential
	}
	item.mu.Lock()
	if item.state != "ready" {
		out := item.result()
		item.mu.Unlock()
		return out, nil
	}
	bound := auth.WithConsentBinding(ctx, item.consent)
	lease, err := h.authorizeConsentOperation(consent.RequireReusableGrant(bound), p, item.surface, true, consent.Control)
	if err != nil {
		item.mu.Unlock()
		return gateway.CredentialResult{}, errPrivateCredential
	}
	lease.Release()
	reason := ""
	if h.credentialPaste == nil || h.credentialPaste.Target == nil {
		reason = "pasteTargetUnavailable"
	} else if item.stage != "password" {
		reason = "pastePasswordStageRequired"
	}
	if reason != "" {
		out := item.result()
		out.State = "needsNativeAction"
		out.AttentionCode = reason
		item.mu.Unlock()
		return out, nil
	}
	item.mu.Unlock()
	return h.credentials.operation(ctx, p, in, "paste")
}

func (s *credentialService) pastePassword(ctx context.Context, p auth.Principal, item *credentialSession, attempt string, manager *vault.Manager, guard func(context.Context) error) (out chrome.CredentialDeliveryResult) {
	out = chrome.CredentialDeliveryResult{DispatchState: "notDispatched", FailureStage: "pasteTargetUnavailable"}
	options := s.host.credentialPaste
	if options == nil || options.Target == nil || item.stage != "password" || guard(ctx) != nil {
		return
	}
	target, err := options.Target(ctx, p, item.surface, item.authority, item.binding, attempt, guard)
	if err != nil || target == nil {
		return
	}
	var clipboard vault.PasswordPasteClipboard
	if options.Clipboard != nil {
		clipboard = options.Clipboard()
	} else {
		clipboard = vault.NewLocalPasswordClipboard()
	}
	if clipboard == nil {
		return
	}
	r := vault.PasteRecordPasswordDuringDelivery(ctx, item.selection, manager, item.protected, item.binding, target, clipboard)
	out.DispatchState = r.DispatchState
	if r.Verified && r.CleanupConfirmed && r.DispatchState == "dispatched" {
		out.FailureStage = ""
		return
	}
	// A successful key/paste receipt without private verification and cleanup
	// is not a filled credential. Keep the durable operation uncertain.
	if out.DispatchState == "dispatched" {
		out.DispatchState = "unknown"
	}
	switch r.Reason {
	case "probeUnconfirmed":
		out.FailureStage = "pasteProbeUnconfirmed"
	case "clipboardUnavailable", "clipboardChanged":
		out.FailureStage = "pasteClipboardUnavailable"
	case "secureTargetChanged":
		out.FailureStage = "pasteTargetChanged"
	case "pasteUnconfirmed":
		out.FailureStage = "pasteUnconfirmed"
	case "verificationUnavailable":
		out.FailureStage = "pasteVerificationUnavailable"
	case "clipboardCleanupUnconfirmed":
		out.FailureStage = "pasteCleanupUnconfirmed"
	}
	return
}
