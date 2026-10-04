package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/mechanize/objective/fixture"
	"github.com/viant/mechanize/script"
)

// Exercise the actual MCP tool boundary, Endly, generated Datly persistence and
// an independent disposable receipt oracle. This case measures a warm execution
// after explicit isolated metadata setup. It does not qualify cold production
// compilation inside the business evidence freshness window.
// Outstanding cold-path boundary: durable.CompleteObjective observes evidence
// before transitionRun invokes its generated writer, while Endly rechecks the
// same evidence age after completion returns. Cold writer preparation belongs
// before that observation in production; fixture warming does not fix it.
func TestMCPWorkflowBusinessOutcome(t *testing.T) {
	for _, mode := range []string{"verified", "wrong-key", "offline", "false"} {
		t.Run(mode, func(t *testing.T) {
			p, err := auth.NewPrincipal("fixture:issuer", "", "mcp-business", []string{"desktop:control"})
			if err != nil {
				t.Fatal(err)
			}
			ctx := auth.WithPrincipal(context.Background(), p)
			store := fixture.New()
			key := "case-1"
			if mode == "wrong-key" {
				key = "case-2"
			}
			store.SetOffline(mode == "offline")
			var oracleObservations atomic.Int32
			evaluator, err := objective.New(map[string]objective.Enrollment{"fixture-receipts": store.Enrollment()})
			if err != nil {
				t.Fatal(err)
			}
			_, file, _, _ := runtime.Caller(0)
			var orchestrator *automation.Runtime
			builder, err := durable.New(durable.Options{SourceRoot: filepath.Dir(filepath.Dir(file)), StorageRoot: t.TempDir(), ObjectiveEvaluator: evaluator, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 0, nil }, StateMutationGuard: func(c context.Context, principal auth.Principal, id string) (func(), error) {
				return orchestrator.StateMutationGuard(c, principal, id)
			}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
				return automation.StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer builder.Close(ctx)
			orchestrator, err = automation.NewWithOptions(builder.Execute, automation.Options{PreparePlan: builder.PreparePlan, CompleteObjective: func(ctx context.Context, p auth.Principal, request automation.CompletionRequest) (automation.BusinessResult, error) {
				if request.Plan.Objective != nil {
					// The application outcome is fixed by the fixture mode, independent
					// of the UI receipt. Observe it at the actual oracle boundary, after
					// compilation/setup, rather than timestamping it before host startup.
					oracleObservations.Add(1)
					store.Put(p, fixture.Receipt{Reference: "fixture:receipt/1", BusinessKey: key, Completed: mode != "false", ObservedAt: time.Now()})
				}
				return builder.CompleteObjective(ctx, p, request)
			}, EvaluatePostcondition: builder.EvaluatePostcondition})
			if err != nil {
				t.Fatal(err)
			}
			policy := script.Policy{AllowedSurfaces: map[string]bool{"com.example.Fixture": true}, Capabilities: map[string]bool{"native:idLocator": true, "native:attributeRead": true}}
			server, err := New(Dependencies{Runtime: orchestrator, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return policy, nil }})
			if err != nil {
				t.Fatal(err)
			}
			client := server.AsClient(ctx)
			if _, err = client.Initialize(ctx); err != nil {
				t.Fatal(err)
			}
			call := func(name string, args map[string]any, target any) {
				t.Helper()
				r, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: args})
				if err != nil {
					t.Fatal(err)
				}
				if r.IsError != nil && *r.IsError {
					t.Fatalf("%s: %+v", name, r)
				}
				encoded, err := json.Marshal(r.StructuredContent)
				if err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(encoded, target); err != nil {
					t.Fatal(err)
				}
			}
			var session SessionRef
			call("mechanize_session_open", map[string]any{}, &session)
			defer orchestrator.Close(ctx, session.SessionID)
			// Warm the real generated plan/intent/outcome/transition components
			// through one inert readonly setup run in this same isolated host. The
			// setup deadline covers metadata compilation only; the authored main
			// step deadline, 30s oracle freshness and 20s execution wait stay intact.
			warmPlan, err := script.Compile(`app("com.example.Fixture").getById("status").read("value")`)
			if err != nil {
				t.Fatal(err)
			}
			warmPlan.Steps[0].TimeoutMs = 120000
			setupStarted := time.Now()
			setupCtx, setupCancel := context.WithTimeout(ctx, 120*time.Second)
			warmOp, err := orchestrator.StartPlan(setupCtx, session.SessionID, *warmPlan, nil)
			if err == nil {
				_, err = orchestrator.Wait(setupCtx, session.SessionID, warmOp.ID)
			}
			setupCancel()
			if err != nil {
				t.Fatalf("isolated metadata setup: %v", err)
			}
			warmRun, err := orchestrator.RunReference(ctx, session.SessionID, warmOp.ID)
			if err != nil {
				t.Fatal(err)
			}
			warmState, err := builder.StateGet(ctx, p, warmRun)
			if err != nil || warmState.Status != "paused" || len(warmState.UnresolvedEffects) != 0 || oracleObservations.Load() != 0 {
				t.Fatalf("readonly setup did not materialize stopped components: %+v %v", warmState, err)
			}
			t.Logf("isolated metadata setup completed in %s; main execution is warm", time.Since(setupStarted))
			source := `schemaVersion: 1
requires: {adapters: [fixture-receipts]}
surfaces:
  fixture: {kind: native, bundleId: com.example.Fixture}
objective:
  kind: adapter
  adapter: fixture-receipts
  name: receiptCompleted
  scope: {surfaceRef: fixture}
  inputs: {businessKey: {kind: string, string: case-1}}
  timeoutMs: 30000
  freshnessMs: 30000
  requiredAuthority: authoritative
steps:
  - id: observe-status
    command: 'app("com.example.Fixture").getById("status").read("value")'
`
			var validated Validation
			call("mechanize_script_validate", map[string]any{"source": source, "format": "yaml"}, &validated)
			if !validated.Valid || validated.Plan.Objective == nil {
				t.Fatal("workflow objective lost")
			}
			var started Operation
			mainStarted := time.Now()
			call("mechanize_script_run", map[string]any{"sessionId": session.SessionID, "clientRequestId": mode, "source": source, "format": "yaml"}, &started)
			wait, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			if _, err = orchestrator.Wait(wait, session.SessionID, started.ID); err != nil {
				t.Fatal(err)
			}
			t.Logf("warm main operation completed in %s", time.Since(mainStarted))
			var status Operation
			call("mechanize_operation_status", map[string]any{"sessionId": session.SessionID, "operationId": started.ID}, &status)
			want := "unverified"
			if mode == "verified" {
				want = "succeeded"
			}
			if mode == "false" {
				want = "failed"
			}
			if status.BusinessStatus != want || status.RunID == "" {
				t.Fatalf("unexpected status: %+v", status)
			}
			state, err := builder.StateGet(ctx, p, status.RunID)
			if err != nil {
				t.Fatal(err)
			}
			if oracleObservations.Load() != 1 {
				t.Fatal("main outcome was not independently observed exactly once")
			}
			if want == "unverified" && (status.VerificationState != "unknown" || state.Status != "paused") {
				t.Fatalf("unknown outcome lost: %+v %+v", status, state)
			}
			if want == "succeeded" && (status.VerificationState != "verified" || status.Objective == nil || len(status.Objective.Evidence) != 1 || status.Objective.Evidence[0].BusinessKey != "case-1" || state.Status != "succeeded") {
				t.Fatalf("durable proof missing: %+v %+v", status, state)
			}
			if want == "succeeded" || want == "failed" {
				if status.Objective == nil || status.Objective.ObservedAt.Before(mainStarted) || status.Objective.Authority != objective.Authoritative || state.Status != want {
					t.Fatalf("main business outcome did not use current independent evidence: %+v %+v", status, state)
				}
			}
		})
	}
}

func TestSourceFormatsAreExplicitAndStrict(t *testing.T) {
	for _, tc := range []struct{ source, format string }{
		{`app("com.example.Fixture").getById("status").read("value")`, "javascript"},
		{`{"schemaVersion":1,"schemaVersion":1}`, "json"},
		{"schemaVersion: 1\nschemaVersion: 1", "yaml"},
		{`{"schemaVersion":1}`, ""},
	} {
		if _, err := compileSource(tc.source, tc.format); err == nil {
			t.Fatalf("ambiguous source accepted: %+v", tc)
		}
	}
}
