package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"strings"
	"testing"
)

func TestCredentialMCPClosedOpaqueAndSanitized(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	rt, e := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("ordinary executor invoked")
		return automation.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	fail := false
	bad := false
	safe := CredentialResult{PreparationID: strings.Repeat("a", 64), State: "unknown", DispatchState: "unknown"}
	callback := func(c context.Context, actor auth.Principal, in CredentialRefInput) (CredentialResult, error) {
		calls++
		if auth.NativeHuman(c) || actor.ClientID != p.ClientID {
			t.Fatal("authority changed")
		}
		if fail {
			return CredentialResult{}, errors.New("username-password-canary")
		}
		if bad {
			return CredentialResult{PreparationID: safe.PreparationID, State: "password-canary"}, nil
		}
		return safe, nil
	}
	s, e := New(Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, CredentialApply: callback, CredentialSubmit: callback, CredentialStatus: callback, CredentialResumeManual: callback})
	if e != nil {
		t.Fatal(e)
	}
	client := s.AsClient(ctx)
	if _, e = client.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"mechanize_credential_apply", "mechanize_credential_submit", "mechanize_credential_status", "mechanize_credential_resume_manual"} {
		for _, field := range []string{"password", "username", "recordId", "revision", "nativeHuman", "target", "values", "secret", "clipboard", "clipboardText", "secretValue"} {
			args := map[string]any{"sessionId": "session", "preparationId": safe.PreparationID, field: "secret-canary"}
			out, e := client.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: args})
			if e == nil && (out == nil || out.IsError == nil || !*out.IsError) {
				t.Fatal("unknown field admitted", field)
			}
			raw, _ := json.Marshal(out)
			if strings.Contains(string(raw), "secret-canary") || e != nil && strings.Contains(e.Error(), "secret-canary") {
				t.Fatal("rejected secret-bearing input was echoed")
			}
			if calls != 0 {
				t.Fatal("secret reached callback")
			}
		}
	}
	for _, mode := range []string{"safe", "configuration", "notReady", "advanceDiagnostic", "failure", "bad"} {
		safe.State, safe.DispatchState, safe.AttentionCode = "unknown", "unknown", ""
		if mode == "configuration" {
			safe.State, safe.DispatchState = "needsConfiguration", ""
		}
		if mode == "notReady" || mode == "advanceDiagnostic" {
			safe.State = "needsNativeAction"
			safe.DispatchState = "dispatched"
			safe.AttentionCode = "postSubmitPrivacyNotReady"
			if mode == "advanceDiagnostic" {
				safe.AttentionCode = "postSubmitControlAuthorityUnavailable"
			}
		}
		fail = mode == "failure"
		bad = mode == "bad"
		toolName := "mechanize_credential_apply"
		if mode == "notReady" || mode == "advanceDiagnostic" {
			toolName = "mechanize_credential_status"
		}
		out, e := client.CallTool(ctx, &schema.CallToolRequestParams{Name: toolName, Arguments: map[string]any{"sessionId": "session", "preparationId": safe.PreparationID}})
		raw, _ := json.Marshal(out)
		if strings.Contains(string(raw), "canary") || e != nil && strings.Contains(e.Error(), "canary") {
			t.Fatal("private diagnostics escaped")
		}
		if (mode == "safe" || mode == "configuration" || mode == "notReady" || mode == "advanceDiagnostic") && (e != nil || out.IsError != nil && *out.IsError) {
			t.Fatal(e, out)
		}
		if mode == "notReady" || mode == "advanceDiagnostic" {
			var got CredentialResult
			body, _ := json.Marshal(out.StructuredContent)
			if json.Unmarshal(body, &got) != nil || got.AttentionCode != safe.AttentionCode || got.State != "needsNativeAction" {
				t.Fatal("public not-ready diagnostic was lost", got)
			}
		}
	}
}

func TestCredentialAttentionCodesRejectRawDiagnostics(t *testing.T) {
	r := CredentialResult{PreparationID: strings.Repeat("a", 64), State: "needsNativeAction"}
	for _, code := range []string{"preparationBarrier", "entryProtection", "preparationAuthority", "preparationReservation", "privateBrowserAdmission", "postSubmitPending", "loginRejected", "privateCandidateUnavailable", "privateAuthorityUnavailable", "privateInspectionUnavailable", "privateLeaseUnavailable", "postSubmitAdvanceUnavailable", "postSubmitPrivacyUnavailable"} {
		r.AttentionCode = code
		if !validCredentialResult(r) {
			t.Fatal("closed diagnostic rejected")
		}
	}
	r.AttentionCode = "private-secret-canary"
	if validCredentialResult(r) {
		t.Fatal("raw diagnostic accepted")
	}
}

func TestCredentialPrivacyPhaseProjection(t *testing.T) {
	r := CredentialResult{PreparationID: strings.Repeat("a", 64), State: "needsNativeAction", DispatchState: "dispatched", AttentionCode: "postSubmitPrivacyNotReady"}
	if !validCredentialResult(r) {
		t.Fatal("closed not-ready reply rejected")
	}
	r.AttentionCode += " PRIVATE_CANARY"
	if validCredentialResult(r) {
		t.Fatal("raw not-ready diagnostics admitted")
	}
	for _, phase := range []string{"Admission", "Fence", "Reply", "Commit", "Probe", "Promotion"} {
		r := CredentialResult{PreparationID: strings.Repeat("a", 64), State: "needsNativeAction", DispatchState: "dispatched", AttentionCode: "postSubmitPrivacy" + phase + "Unavailable"}
		if !validCredentialResult(r) {
			t.Fatalf("closed privacy phase rejected: %s", phase)
		}
		r.AttentionCode += " PRIVATE_CANARY"
		if validCredentialResult(r) {
			t.Fatal("untrusted diagnostic content admitted")
		}
	}
}

func TestCredentialRecoveryMCPRejectsSecretAndAuthorityInputs(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	rt, e := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("recovery dispatched input")
		return automation.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	s, e := New(Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, CredentialRecover: func(c context.Context, actor auth.Principal, in CredentialRecoverInput) (CredentialResult, error) {
		calls++
		if auth.NativeHuman(c) || actor.ClientID != p.ClientID {
			t.Fatal("recovery authority changed")
		}
		return CredentialResult{PreparationID: in.PreparationID, State: "recovered"}, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	client := s.AsClient(ctx)
	if _, e = client.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"password", "username", "secretValue", "clipboard", "nativeHuman", "processId", "processStartToken", "cleanupConfirmed"} {
		args := map[string]any{"sessionId": "session", "preparationId": strings.Repeat("a", 64), "retirementRunId": "run", "purpose": "recover", field: "PRIVATE-CANARY"}
		out, e := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_credential_recover", Arguments: args})
		raw, _ := json.Marshal(out)
		if e == nil && (out == nil || out.IsError == nil || !*out.IsError) {
			t.Fatal("authority input admitted")
		}
		if calls != 0 || strings.Contains(string(raw), "PRIVATE-CANARY") || e != nil && strings.Contains(e.Error(), "PRIVATE-CANARY") {
			t.Fatal("rejected private input escaped")
		}
	}
	out, e := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_credential_recover", Arguments: map[string]any{"sessionId": "session", "preparationId": strings.Repeat("a", 64), "retirementRunId": "run", "purpose": "recover"}})
	if e != nil || out == nil || out.IsError != nil && *out.IsError || calls != 1 {
		t.Fatal("opaque recovery unavailable", e)
	}
}

func TestCredentialProjectionAcceptsOnlyClosedDeliveryPhaseDiagnostics(t *testing.T) {
	for _, phase := range []string{"deliveryAdmission", "privateBindingFresh", "localVaultRead", "deliveryLane", "deliveryAuthority", "deliveryEncoding", "deliveryTransport", "privateFormReply", "postLoginDocumentUnavailable"} {
		r := CredentialResult{PreparationID: strings.Repeat("a", 64), State: "needsNativeAction", DispatchState: "notDispatched", AttentionCode: phase}
		if !validCredentialResult(r) {
			t.Fatalf("closed phase hidden: %s", phase)
		}
	}
	for _, phase := range []string{"PASSWORD-CANARY", "deliveryTransport: secret-value", "https://private.test/?password=CANARY"} {
		r := CredentialResult{PreparationID: strings.Repeat("a", 64), State: "needsNativeAction", AttentionCode: phase}
		if validCredentialResult(r) {
			t.Fatal("untrusted private diagnostic accepted")
		}
	}
}

func TestManualPrivacyProjectionAcceptsOnlyClosedDiagnostics(t *testing.T) {
	for _, suffix := range []string{"SourceUnavailable", "ConsentUnavailable", "AbsenceUnavailable", "StagingUnavailable", "SelectionUnavailable", "QualificationUnavailable", "TransitionUnavailable", "CleanupUnavailable", "InvalidRequest", "AuthorityChanged", "Expired", "Busy", "UnknownEffects", "LifecycleInhibited", "SourceTabPresent", "InventoryUnavailable", "CandidateUnavailable", "CandidateAmbiguous", "CandidateChanged", "DocumentNotReady", "RedactionUnavailable"} {
		if !validCredentialResult(CredentialResult{PreparationID: strings.Repeat("a", 64), State: "needsNativeAction", AttentionCode: "manualPrivacy" + suffix}) {
			t.Fatal("closed diagnosis hidden", suffix)
		}
	}
	for _, code := range []string{"manualPrivacyUnknown", "manualPrivacySourceTabPresent:PRIVATE-CANARY", "manualPrivacyhttps://private.test", "PRIVATE-CANARY"} {
		if validCredentialResult(CredentialResult{PreparationID: strings.Repeat("a", 64), State: "needsNativeAction", AttentionCode: code}) {
			t.Fatal("untrusted diagnostic admitted")
		}
	}
}

func TestCredentialAdvanceDiagnosticClosedStates(t *testing.T) {
	for _, code := range []string{"postSubmitAdmissionUnavailable", "postSubmitControlAuthorityUnavailable", "postSubmitFlowUnavailable", "postSubmitTransportUnavailable", "postSubmitReplyUnavailable"} {
		r := CredentialResult{PreparationID: strings.Repeat("a", 64), State: "needsNativeAction", AttentionCode: code, DispatchState: "dispatched"}
		if !validCredentialResult(r) {
			t.Fatal(code)
		}
		r.State = "ready"
		if validCredentialResult(r) {
			t.Fatal("phase allowed before submit")
		}
	}
}
