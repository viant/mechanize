package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestEffectReconciliationToolClosedInputAndOwnedSession(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	other, _ := auth.NewPrincipal("fixture", "", "bob", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	runtime, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("reconciliation tool dispatched input")
		return automation.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtime.Open(ctx, "reconciliation")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	commitWithCleanupError := false
	server, err := New(Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, EffectReconcile: func(c context.Context, actor auth.Principal, in durable.EffectReconcileRequest) (durable.EffectReconcileResult, error) {
		calls++
		if actor.Namespace != p.Namespace || in.RunID != "run" || in.RequestID != "request" {
			t.Fatal("request identity changed")
		}
		binding, ok := auth.ConsentBindingFromContext(c)
		if !ok || binding.SessionID != session.SessionID || binding.Purpose != "Resolve navigation" {
			t.Fatal("observe binding missing")
		}
		result := durable.EffectReconcileResult{CommitConfirmed: true, EffectID: "effect", State: "confirmed"}
		if commitWithCleanupError {
			result.Reason = "reconciliation guard cleanup unconfirmed"
			return result, errors.New("fixture cleanup error")
		}
		return result, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	client := server.AsClient(ctx)
	if _, err = client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range listed.Tools {
		if tool.Name == "mechanize_effect_reconcile" {
			raw, _ := json.Marshal(tool.InputSchema)
			if !strings.Contains(string(raw), `"additionalProperties":false`) {
				t.Fatal("reconciliation schema not closed")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("reconciliation tool not advertised")
	}
	args := map[string]any{"sessionId": session.SessionID, "purpose": "Resolve navigation", "runId": "run", "planId": "plan", "attemptId": "attempt", "effectId": "effect", "expectedRunRevision": 3, "expectedEffectRevision": 2, "requestId": "request"}
	for _, field := range []string{"success", "evidence", "predicate", "namespace", "sql"} {
		bad := map[string]any{}
		for k, v := range args {
			bad[k] = v
		}
		bad[field] = "untrusted"
		out, e := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_effect_reconcile", Arguments: bad})
		if e == nil && (out.IsError == nil || !*out.IsError) {
			t.Fatalf("caller field %s accepted", field)
		}
	}
	if calls != 0 {
		t.Fatal("invalid input reached resolver")
	}
	out, e := client.CallTool(auth.WithPrincipal(ctx, other), &schema.CallToolRequestParams{Name: "mechanize_effect_reconcile", Arguments: args})
	if e == nil && (out.IsError == nil || !*out.IsError) {
		t.Fatal("foreign session accepted")
	}
	if calls != 0 {
		t.Fatal("foreign request reached resolver")
	}
	out, e = client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_effect_reconcile", Arguments: args})
	if e != nil || out.IsError != nil && *out.IsError || calls != 1 {
		t.Fatalf("owned request failed %+v %v", out, e)
	}
	commitWithCleanupError = true
	out, e = client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_effect_reconcile", Arguments: args})
	if e != nil || out.IsError == nil || !*out.IsError {
		t.Fatal("committed cleanup failure concealed")
	}
	raw, _ := json.Marshal(out.StructuredContent)
	if !strings.Contains(string(raw), `"commitConfirmed":true`) {
		t.Fatal("commit confirmation lost on cleanup error")
	}
}
