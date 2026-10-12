package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
	"io"
)

type CredentialPrepareInput struct {
	SessionID string        `json:"sessionId"`
	GrantID   string        `json:"grantId,omitempty"`
	Purpose   string        `json:"purpose"`
	Surface   model.Surface `json:"surface"`
}
type CredentialRefInput struct {
	SessionID     string `json:"sessionId"`
	PreparationID string `json:"preparationId"`
}
type CredentialRecoverInput struct {
	SessionID       string `json:"sessionId"`
	PreparationID   string `json:"preparationId"`
	RetirementRunID string `json:"retirementRunId"`
	Purpose         string `json:"purpose"`
}
type CredentialRecover func(context.Context, auth.Principal, CredentialRecoverInput) (CredentialResult, error)

// CredentialResult is the complete public projection. It never reports login
// success or includes Vault refs, values, record names, documents or raw diagnostics.
type CredentialResult struct {
	PreparationID string         `json:"preparationId"`
	State         string         `json:"state"`
	DispatchState string         `json:"dispatchState,omitempty"`
	Stage         string         `json:"stage,omitempty"`
	AttentionCode string         `json:"attentionCode,omitempty"`
	Surface       *model.Surface `json:"surface,omitempty"`
}
type CredentialPrepare func(context.Context, auth.Principal, CredentialPrepareInput) (CredentialResult, error)
type CredentialOperation func(context.Context, auth.Principal, CredentialRefInput) (CredentialResult, error)

func registerCredentials(base *protocol.DefaultHandler, d Dependencies) error {
	if d.CredentialResumeManual != nil {
		if e := credentialTool(base, "mechanize_credential_resume_manual", (*CredentialRefInput)(nil), func(c context.Context, p auth.Principal, raw []byte) (CredentialResult, error) {
			var in CredentialRefInput
			if e := decodeCredentialInput(raw, &in); e != nil {
				return CredentialResult{}, e
			}
			return d.CredentialResumeManual(c, p, in)
		}); e != nil {
			return e
		}
	}
	if d.CredentialRecover != nil {
		if e := credentialTool(base, "mechanize_credential_recover", (*CredentialRecoverInput)(nil), func(c context.Context, p auth.Principal, raw []byte) (CredentialResult, error) {
			var in CredentialRecoverInput
			if e := decodeCredentialInput(raw, &in); e != nil {
				return CredentialResult{}, e
			}
			return d.CredentialRecover(c, p, in)
		}); e != nil {
			return e
		}
	}
	if d.CredentialPrepare != nil {
		if e := credentialTool(base, "mechanize_credential_prepare", (*CredentialPrepareInput)(nil), func(c context.Context, p auth.Principal, raw []byte) (CredentialResult, error) {
			var in CredentialPrepareInput
			if e := decodeCredentialInput(raw, &in); e != nil {
				return CredentialResult{}, e
			}
			return d.CredentialPrepare(c, p, in)
		}); e != nil {
			return e
		}
	}
	for _, v := range []struct {
		name string
		call CredentialOperation
	}{{"mechanize_credential_apply", d.CredentialApply}, {"mechanize_credential_submit", d.CredentialSubmit}, {"mechanize_credential_status", d.CredentialStatus}} {
		if v.call == nil {
			continue
		}
		call := v.call
		if e := credentialTool(base, v.name, (*CredentialRefInput)(nil), func(c context.Context, p auth.Principal, raw []byte) (CredentialResult, error) {
			var in CredentialRefInput
			if e := decodeCredentialInput(raw, &in); e != nil {
				return CredentialResult{}, e
			}
			return call(c, p, in)
		}); e != nil {
			return e
		}
	}
	return nil
}
func decodeCredentialInput(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 8192 || d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("private credential input unavailable")
	}
	return nil
}
func credentialTool(base *protocol.DefaultHandler, name string, typ any, call func(context.Context, auth.Principal, []byte) (CredentialResult, error)) error {
	var input schema.ToolInputSchema
	if e := input.Load(typ); e != nil {
		return e
	}
	extra, ok := input.AdditionalProperties.(map[string]any)
	if !ok {
		extra = map[string]any{}
	}
	extra["additionalProperties"] = false
	input.AdditionalProperties = extra
	var output schema.ToolOutputSchema
	if e := output.Load((*CredentialResult)(nil)); e != nil {
		return e
	}
	base.Registry.RegisterToolWithSchema(name, "Private credential operation using existing reusable control consent and one saved credential bound to the exact website origin. Status privately qualifies the form before apply. Opaque reference and scalar state only; no secret inputs, values, record lookup or login-success assertion. Unknown attempts are never replayed.", input, &output, func(ctx context.Context, r *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		unavailable := func() (*schema.CallToolResult, *jsonrpc.Error) {
			return failure(errors.New("private credential operation unavailable"))
		}
		if r == nil {
			return unavailable()
		}
		raw, e := json.Marshal(r.Params.Arguments)
		if e != nil || len(raw) > 8192 {
			return unavailable()
		}
		p, e := auth.FromContext(ctx)
		if e != nil {
			return unavailable()
		}
		out, e := call(ctx, p, raw)
		if e != nil || !validCredentialResultForTool(name, out) {
			return unavailable()
		}
		return result(out)
	})
	return nil
}

func validPreparationScopeAttention(code string) bool {
	switch code {
	case "scopeChanged", "scopeSourcePresent", "scopeTargetProtected", "scopeInventoryUnavailable", "scopeLimit", "scopeUnsupported", "scopePreflightBusy", "scopeUnavailable", "scopeOtherLoginHeld":
		return true
	}
	return false
}
func validCredentialResultForTool(name string, r CredentialResult) bool {
	// Cleanup can refuse before a new preparation exists. No other operation,
	// state or capability-bearing field may use this narrow missing-ID result.
	if r.PreparationID == "" {
		return name == "mechanize_credential_prepare" && r.State == "needsNativeAction" && r.Stage == "" && r.DispatchState == "" && r.Surface == nil && validPreparationScopeAttention(r.AttentionCode)
	}
	return validCredentialResult(r)
}

func validCredentialResult(r CredentialResult) bool {
	b, e := hex.DecodeString(r.PreparationID)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != r.PreparationID {
		return false
	}
	switch r.State {
	case "awaitingNativeApproval", "awaitingPreflight", "ready", "protected", "filled", "submitted", "unknown", "needsNativeAction", "needsConfiguration", "privacyReady", "recovered":
	default:
		return false
	}
	switch r.Stage {
	case "", "username", "password", "pair", "challenge", "unavailable", "privacyReady", "pending", "rejected":
	default:
		return false
	}
	switch r.DispatchState {
	case "", "unknown", "notDispatched", "dispatched":
	default:
		return false
	}
	switch r.AttentionCode {
	case "postSubmitAdmissionUnavailable", "postSubmitControlAuthorityUnavailable", "postSubmitFlowUnavailable", "postSubmitTransportUnavailable", "postSubmitReplyUnavailable":
		if r.State != "needsNativeAction" && r.State != "submitted" {
			return false
		}
	case "manualPrivacySourceUnavailable", "manualPrivacyConsentUnavailable", "manualPrivacyAbsenceUnavailable", "manualPrivacyStagingUnavailable", "manualPrivacySelectionUnavailable", "manualPrivacyQualificationUnavailable", "manualPrivacyTransitionUnavailable", "manualPrivacyCleanupUnavailable", "manualPrivacyInvalidRequest", "manualPrivacyAuthorityChanged", "manualPrivacyExpired", "manualPrivacyBusy", "manualPrivacyUnknownEffects", "manualPrivacyLifecycleInhibited", "manualPrivacySourceTabPresent", "manualPrivacyInventoryUnavailable", "manualPrivacyCandidateUnavailable", "manualPrivacyCandidateAmbiguous", "manualPrivacyCandidateChanged", "manualPrivacyDocumentNotReady", "manualPrivacyRedactionUnavailable":
	case "postSubmitPrivacyNotReady", "postSubmitPrivacyAdmissionUnavailable", "postSubmitPrivacyFenceUnavailable", "postSubmitPrivacyReplyUnavailable", "postSubmitPrivacyCommitUnavailable", "postSubmitPrivacyProbeUnavailable", "postSubmitPrivacyPromotionUnavailable":
	case "", "preparationBarrier", "entryProtection", "preparationAuthority", "preparationReservation", "privateBrowserAdmission", "postSubmitPending", "loginRejected", "privateCandidateUnavailable", "privateCandidateAmbiguous", "privateChannelBusy", "privateAuthorityUnavailable", "privateInspectionUnavailable", "privateLeaseUnavailable", "postSubmitAdvanceUnavailable", "postSubmitPrivacyUnavailable", "postLoginDocumentUnavailable", "deliveryAdmission", "privateBindingFresh", "localVaultRead", "deliveryLane", "deliveryAuthority", "deliveryEncoding", "deliveryTransport", "privateFormReply":
	default:
		if r.State != "needsNativeAction" || !(chrome.ValidCredentialInspectionAttention(r.AttentionCode) || validPreparationScopeAttention(r.AttentionCode) || r.AttentionCode == "sourceScopePersistence" || r.AttentionCode == "scopeSourceRetirement") {
			return false
		}
	}
	if r.State == "privacyReady" && (r.Surface == nil || r.Stage != "privacyReady" || r.DispatchState == "unknown") {
		return false
	}
	if r.Surface != nil {
		s := r.Surface
		if r.State != "privacyReady" || s.Kind != "web" || (vault.Target{Origin: s.Origin, Account: "opaque"}).Validate() != nil || s.TabID == "" || s.BundleID != "" || s.Title != "" || s.ProcessID != 0 || s.ProcessStartToken != "" {
			return false
		}
	}
	return true
}
