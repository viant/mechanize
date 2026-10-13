package mcp

import (
	"context"
	"encoding/json"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestMCPPlainActionAndScriptCompleteWithoutInventingVerification(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture", "", "plain-mcp", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	var calls atomic.Int32
	var rt *integration.Runtime
	b, e := durable.New(durable.Options{SourceRoot: filepath.Dir(filepath.Dir(file)), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, StateMutationGuard: func(c context.Context, a auth.Principal, id string) (func(), error) {
		return rt.StateMutationGuard(c, a, id)
	}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		calls.Add(1)
		return integration.StepResult{DispatchState: "dispatched", VerificationState: "unknown"}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close(ctx)
	rt, e = integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, CompleteObjective: b.CompleteObjective, AttachInitialOperation: func(c context.Context, a auth.Principal, run string, rev int, session, op string) error {
		_, e := b.AttachOperation(c, a, run, rev, session, op)
		return e
	}})
	if e != nil {
		t.Fatal(e)
	}
	policy := script.Policy{AllowedSurfaces: map[string]bool{"com.example.Fixture": true}, AllowMutation: true, Capabilities: map[string]bool{"native:semanticPress": true, "native:idLocator": true}}
	server, e := New(Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return policy, nil }})
	if e != nil {
		t.Fatal(e)
	}
	client := server.AsClient(ctx)
	if _, e = client.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	call := func(name string, args map[string]any, out any) {
		t.Helper()
		result, e := client.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: args})
		if e != nil || result.IsError != nil && *result.IsError {
			t.Fatal(name, e, result)
		}
		raw, _ := json.Marshal(result.StructuredContent)
		if e = json.Unmarshal(raw, out); e != nil {
			t.Fatal(e)
		}
	}
	var session SessionRef
	call("mechanize_session_open", map[string]any{}, &session)
	defer rt.Close(ctx, session.SessionID)
	for _, tool := range []string{"mechanize_step_run", "mechanize_script_run"} {
		t.Run(tool, func(t *testing.T) {
			source := `app("com.example.Fixture").getById("first").click()`
			n := 1
			if tool == "mechanize_script_run" {
				source += "\n" + `app("com.example.Fixture").getById("second").click()`
				n = 2
			}
			plan, e := script.Compile(source)
			if e != nil {
				t.Fatal(e)
			}
			for i := range plan.Steps {
				plan.Steps[i].Effect.BusinessKey = map[string]model.Value{"action": {Kind: model.StringValue, String: plan.Steps[i].ID}}
			}
			encoded, _ := json.Marshal(plan)
			args := map[string]any{"sessionId": session.SessionID, "clientRequestId": tool, "source": string(encoded), "format": "json"}
			before := calls.Load()
			var started Operation
			call(tool, args, &started)
			wait, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			if _, e = rt.Wait(wait, session.SessionID, started.ID); e != nil {
				t.Fatal(e)
			}
			var status Operation
			call("mechanize_operation_status", map[string]any{"sessionId": session.SessionID, "operationId": started.ID}, &status)
			if status.ExecutionStatus != "succeeded" || status.BusinessStatus != "unverified" || status.VerificationState != "unverified" || status.Objective != nil || status.ExecutionFailure != nil {
				t.Fatal("plain action became failure or business success", status)
			}
			var replay Operation
			call(tool, args, &replay)
			if replay.ID != started.ID || calls.Load() != before+int32(n) {
				t.Fatal("same request repeated input")
			}
			state, e := b.StateGet(ctx, p, status.RunID)
			if e != nil || len(state.UnresolvedEffects) != 0 || len(state.Progress) != 0 {
				t.Fatal("plain action invented UNKNOWN or milestone", e)
			}
		})
	}
}
