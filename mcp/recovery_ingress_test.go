package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/viant/datly/exec"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data/recoveryload"
	repairs "github.com/viant/mechanize/engine/recovery"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestRecoveryIngressClosedOwnedConsent(t *testing.T) {
	principal, err := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
	if err != nil {
		t.Fatal(err)
	}
	principal.ClientID, principal.ClientName = "fixture-client", "Fixture Client"
	ctx := auth.WithPrincipal(context.Background(), principal)
	runtime, err := integration.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		t.Fatal("recovery ingress dispatched input")
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtime.Open(ctx, "repair ingress")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx, session.SessionID)
	plan, err := script.Compile(`app("fixture.app").getById("result").read("name")`)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(struct {
		Plan model.Plan `json:"plan"`
	}{Plan: *plan})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(envelope)
	contentHash := hex.EncodeToString(digest[:])
	namespace, runID, planID, objectiveID, status, revision := principal.Namespace, "owned-run", "original-plan", "objective", "paused", 3
	content := string(envelope)
	row := &recoveryload.RecoveryRun{Namespace: &namespace, Id: &runID, PlanId: &planID, ObjectiveId: &objectiveID, Status: &status, Revision: &revision, Plans: []*recoveryload.PlanRevision{{Namespace: &namespace, Id: &planID, ObjectiveId: &objectiveID, ContentHash: &contentHash, ContentJson: &content}}}
	invocations, authorizations := 0, 0
	privateFailure := false
	service, err := repairs.New(repairs.Options{Invoke: func(c context.Context, p auth.Principal, request exec.ComponentRequest) (any, error) {
		invocations++
		in, ok := request.Input.(*recoveryload.LoadRecoveryInput)
		binding, bound := auth.ConsentBindingFromContext(c)
		if !ok || in.RunID != runID || in.Namespace != namespace || !reflect.DeepEqual(p, principal) || !bound || binding != (auth.ConsentBinding{SessionID: session.SessionID, Purpose: "Inspect stopped fixture"}) {
			t.Fatalf("private recovery call lost exact identity/reference/consent: request=%+v actor=%+v binding=%+v", in, p, binding)
		}
		if privateFailure {
			return nil, errors.New("private-payload-secret")
		}
		return &recoveryload.LoadRecoveryOutput{Data: []*recoveryload.RecoveryRun{row}}, nil
	}, Authorize: func(c context.Context, p auth.Principal, surface model.Surface) error {
		authorizations++
		binding, bound := auth.ConsentBindingFromContext(c)
		if !reflect.DeepEqual(p, principal) || !bound || binding != (auth.ConsentBinding{SessionID: session.SessionID, Purpose: "Inspect stopped fixture"}) {
			t.Fatal("recovery authorization lost consent binding")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Dependencies{Runtime: runtime, Recovery: service, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	client := s.AsClient(ctx)
	if _, err = client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range listed.Tools {
		if tool.Name == "mechanize_recovery_context" || tool.Name == "mechanize_recovery_admit" {
			raw, err := json.Marshal(tool.InputSchema)
			if err != nil || !strings.Contains(string(raw), `"additionalProperties":false`) || !strings.Contains(string(raw), `"sessionId"`) || !strings.Contains(string(raw), `"expectedPlanId"`) {
				t.Fatalf("recovery consent schema is not closed/complete: %s %v", raw, err)
			}
		}
	}
	for _, name := range []string{"mechanize_recovery_context", "mechanize_recovery_admit"} {
		t.Run(name, func(t *testing.T) {
			args := func() map[string]any {
				in := map[string]any{"sessionId": session.SessionID, "purpose": "Inspect stopped fixture", "runId": runID, "expectedPlanId": planID, "expectedRevision": revision}
				if name == "mechanize_recovery_admit" {
					in["patch"] = map[string]any{"baseHash": "base", "objectiveHash": "objective", "remainingSteps": []any{}, "evidenceRefs": []string{"evidence"}}
				}
				return in
			}
			assertRejected := func(t *testing.T, c context.Context, in map[string]any) {
				t.Helper()
				beforeCalls, beforeAuthorizations := invocations, authorizations
				out, err := client.CallTool(c, &schema.CallToolRequestParams{Name: name, Arguments: in})
				if err == nil && (out == nil || out.IsError == nil || !*out.IsError) {
					t.Fatalf("untrusted recovery ingress accepted: %+v", out)
				}
				if invocations != beforeCalls || authorizations != beforeAuthorizations {
					t.Fatal("untrusted ingress reached recovery service")
				}
				encoded, _ := json.Marshal(out)
				if strings.Contains(string(encoded), "private-payload-secret") || err != nil && strings.Contains(err.Error(), "private-payload-secret") {
					t.Fatal("rejected payload leaked into error")
				}
			}
			for _, field := range []string{"namespace", "grantId", "observation", "verified", "contracts", "commitConfirmed", "private-payload-secret"} {
				t.Run("reject_"+field, func(t *testing.T) {
					in := args()
					in[field] = "private-payload-secret"
					assertRejected(t, ctx, in)
				})
			}
			for _, field := range []string{"sessionId", "purpose"} {
				t.Run("missing_"+field, func(t *testing.T) {
					in := args()
					delete(in, field)
					assertRejected(t, ctx, in)
				})
			}
			t.Run("oversized", func(t *testing.T) {
				in := args()
				in["purpose"] = strings.Repeat("private-payload-secret", 14000)
				assertRejected(t, ctx, in)
			})
			t.Run("unknown_session", func(t *testing.T) {
				in := args()
				in["sessionId"] = "missing-session"
				assertRejected(t, ctx, in)
			})
			t.Run("missing_principal", func(t *testing.T) { assertRejected(t, context.Background(), args()) })
			t.Run("foreign_principal", func(t *testing.T) {
				other, err := auth.NewPrincipal("fixture", "", "bob", []string{"desktop:observe"})
				if err != nil {
					t.Fatal(err)
				}
				assertRejected(t, auth.WithPrincipal(context.Background(), other), args())
			})
			t.Run("foreign_client", func(t *testing.T) {
				other := principal
				other.ClientID = "foreign-client"
				assertRejected(t, auth.WithPrincipal(context.Background(), other), args())
			})
			before := invocations
			bound := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "stale-session", Purpose: "old purpose", GrantID: "old-grant"})
			out, err := client.CallTool(bound, &schema.CallToolRequestParams{Name: name, Arguments: args()})
			if err != nil || out == nil || out.IsError != nil && *out.IsError || invocations != before+1 {
				t.Fatalf("owned recovery request failed: %+v %v", out, err)
			}
			body := out.StructuredContent.(map[string]any)
			if body["status"] != "needsAttention" {
				t.Fatalf("unqualified recovery hooks promised readiness: %+v", body)
			}
			if name == "mechanize_recovery_context" {
				ref := body["reference"].(map[string]any)
				if ref["runId"] != runID || ref["planId"] != planID || ref["revision"] != float64(revision) || body["reason"] != "trusted fresh observation, evidence and qualified recovery contracts unavailable" {
					t.Fatalf("exact context request changed: %+v", body)
				}
			} else if body["reason"] != "stopped runtime repair/lineage admission binding unavailable" || body["commitConfirmed"] != false || body["readyToResume"] != false {
				t.Fatalf("exact admission request changed: %+v", body)
			}
			privateFailure = true
			out, err = client.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: args()})
			privateFailure = false
			if err != nil || out == nil || out.IsError == nil || !*out.IsError {
				t.Fatalf("private component error concealed: %+v %v", out, err)
			}
			encoded, _ := json.Marshal(out)
			if strings.Contains(string(encoded), "private-payload-secret") {
				t.Fatal("private component error exposed")
			}
			if name == "mechanize_recovery_admit" {
				in := args()
				in["patch"] = map[string]any{"private-payload-secret": "secret"}
				out, err = client.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: in})
				if err != nil || out == nil || out.IsError == nil || !*out.IsError {
					t.Fatal("forged nested patch accepted")
				}
				encoded, _ = json.Marshal(out)
				if strings.Contains(string(encoded), "private-payload-secret") {
					t.Fatal("patch decoder exposed payload field")
				}
			}
		})
	}
}
