package mcp

import (
	"context"
	"testing"

	"github.com/viant/datly/exec"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	repairs "github.com/viant/mechanize/engine/recovery"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestRecoveryToolDiscoveryAndDeniedIdentity(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
	ctx := auth.WithPrincipal(context.Background(), p)
	invocations := 0
	service, err := repairs.New(repairs.Options{Invoke: func(context.Context, auth.Principal, exec.ComponentRequest) (any, error) {
		invocations++
		return nil, auth.ErrUnauthorized
	}, Authorize: func(context.Context, auth.Principal, model.Surface) error { return auth.ErrUnauthorized }})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := integration.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		t.Fatal("recovery tools dispatched")
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Dependencies{Runtime: runtime, Recovery: service, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	client := server.AsClient(ctx)
	if _, err = client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	tools, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, tool := range tools.Tools {
		seen[tool.Name] = true
	}
	if !seen["mechanize_recovery_context"] || !seen["mechanize_recovery_admit"] {
		t.Fatal("guarded recovery tools absent")
	}
	session, err := runtime.Open(ctx, "recovery fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx, session.SessionID)
	for _, name := range []string{"mechanize_recovery_context", "mechanize_recovery_admit"} {
		args := map[string]any{"sessionId": session.SessionID, "purpose": "Inspect repair", "runId": "owned-run", "expectedPlanId": "plan", "expectedRevision": 1}
		if name == "mechanize_recovery_admit" {
			args["patch"] = map[string]any{"baseHash": "untrusted", "objectiveHash": "untrusted", "remainingSteps": []any{}, "evidenceRefs": []string{"untrusted"}}
		}
		r, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: name, Arguments: args})
		if err != nil || r.IsError == nil || !*r.IsError {
			t.Fatalf("identity rejected recovery must fail: %+v %v", r, err)
		}
	}
	if invocations != 0 {
		t.Fatal("denied actor reached private components")
	}
}
