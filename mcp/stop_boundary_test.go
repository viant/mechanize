package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestStopBoundaryToolClosedInputAndOwnedSession(t *testing.T) {
	p, err := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID, p.ClientName = "fixture-agent", "Fixture Agent"
	ctx := auth.WithPrincipal(context.Background(), p)
	runtime, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("stop boundary dispatched input")
		return automation.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtime.Open(ctx, "stop boundary fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx, session.SessionID)
	calls := 0
	wantRequest := durable.StopBoundaryRequest{RunID: "run", PlanID: "plan", RequestID: "stable-request", ExpectedRunRevision: 7}
	wantResult := durable.StopBoundaryResult{CommitConfirmed: true, BoundaryID: "boundary", ResumeAdmitted: false, Run: &durable.ReconciliationRunState{RunID: "run", PlanID: "plan", Revision: 8, Status: "paused", NeedsAttention: true, UnresolvedEffectIDs: []string{"unknown-effect"}, UnresolvedCount: 1}}
	callbackError := false
	s, err := New(Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, StateStopBoundary: func(c context.Context, actor auth.Principal, in durable.StopBoundaryRequest) (durable.StopBoundaryResult, error) {
		calls++
		if !reflect.DeepEqual(actor, p) || in != wantRequest {
			t.Fatalf("callback identity or exact references changed: actor=%+v request=%+v", actor, in)
		}
		binding, ok := auth.ConsentBindingFromContext(c)
		if !ok || binding != (auth.ConsentBinding{SessionID: session.SessionID, Purpose: "Record stopped run"}) {
			t.Fatalf("callback consent binding changed: %+v", binding)
		}
		if callbackError {
			return wantResult, errors.New("private cleanup error")
		}
		return wantResult, nil
	}})
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
	found := false
	for _, tool := range listed.Tools {
		if tool.Name == "mechanize_state_stop_boundary" {
			found = true
			raw, err := json.Marshal(tool.InputSchema)
			if err != nil || !strings.Contains(string(raw), `"additionalProperties":false`) {
				t.Fatalf("stop boundary schema is not closed: %s %v", raw, err)
			}
		}
	}
	if !found {
		t.Fatal("stop boundary tool not advertised")
	}
	args := map[string]any{"sessionId": session.SessionID, "purpose": "Record stopped run", "runId": "run", "planId": "plan", "requestId": "stable-request", "expectedRunRevision": 7}
	cloneArgs := func() map[string]any {
		copy := make(map[string]any, len(args))
		for key, value := range args {
			copy[key] = value
		}
		return copy
	}
	assertRejected := func(t *testing.T, c context.Context, arguments map[string]any) {
		t.Helper()
		out, err := client.CallTool(c, &schema.CallToolRequestParams{Name: "mechanize_state_stop_boundary", Arguments: arguments})
		if err == nil && (out == nil || out.IsError == nil || !*out.IsError) {
			t.Fatalf("request accepted: %+v", out)
		}
		if calls != 0 {
			t.Fatal("rejected request reached callback")
		}
	}
	for _, field := range []string{"quiescenceProof", "commitConfirmed", "resumeAdmitted", "namespace", "grantId", "unknownField"} {
		t.Run("reject_"+field, func(t *testing.T) {
			bad := cloneArgs()
			bad[field] = "forged"
			assertRejected(t, ctx, bad)
		})
	}
	for _, field := range []string{"sessionId", "purpose"} {
		t.Run("missing_"+field, func(t *testing.T) {
			bad := cloneArgs()
			delete(bad, field)
			assertRejected(t, ctx, bad)
		})
	}
	t.Run("oversized_purpose", func(t *testing.T) {
		bad := cloneArgs()
		bad["purpose"] = strings.Repeat("x", 4001)
		assertRejected(t, ctx, bad)
	})
	t.Run("unknown_session", func(t *testing.T) {
		bad := cloneArgs()
		bad["sessionId"] = "missing-session"
		assertRejected(t, ctx, bad)
	})
	t.Run("missing_principal", func(t *testing.T) { assertRejected(t, context.Background(), cloneArgs()) })
	t.Run("foreign_principal", func(t *testing.T) {
		other, err := auth.NewPrincipal("fixture", "", "bob", nil)
		if err != nil {
			t.Fatal(err)
		}
		assertRejected(t, auth.WithPrincipal(context.Background(), other), cloneArgs())
	})
	t.Run("foreign_client", func(t *testing.T) {
		other := p
		other.ClientID = "other-agent"
		assertRejected(t, auth.WithPrincipal(context.Background(), other), cloneArgs())
	})
	// A preexisting context binding must not substitute another session or grant.
	boundCtx := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "other-session", Purpose: "other purpose", GrantID: "forged-grant"})
	out, err := client.CallTool(boundCtx, &schema.CallToolRequestParams{Name: "mechanize_state_stop_boundary", Arguments: args})
	if err != nil || out == nil || out.IsError != nil && *out.IsError || calls != 1 {
		t.Fatalf("owned stop boundary failed: %+v %v calls=%d", out, err, calls)
	}
	checkResult := func(out *schema.CallToolResult) {
		t.Helper()
		raw, err := json.Marshal(out.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		var got durable.StopBoundaryResult
		if err = json.Unmarshal(raw, &got); err != nil || !reflect.DeepEqual(got, wantResult) {
			t.Fatalf("structured stop boundary result changed: %s %v", raw, err)
		}
		if strings.Contains(string(raw), "private cleanup error") {
			t.Fatal("callback error details exposed in committed result")
		}
	}
	checkResult(out)
	callbackError = true
	out, err = client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_state_stop_boundary", Arguments: args})
	if err != nil || out == nil || out.IsError == nil || !*out.IsError || calls != 2 {
		t.Fatalf("committed callback error concealed: %+v %v calls=%d", out, err, calls)
	}
	checkResult(out)
	wantResult.CommitConfirmed = false
	out, err = client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_state_stop_boundary", Arguments: args})
	if err != nil || out == nil || out.IsError == nil || !*out.IsError || calls != 3 {
		t.Fatalf("uncommitted callback error accepted: %+v %v calls=%d", out, err, calls)
	}
	var rejected map[string]any
	raw, err := json.Marshal(out.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &rejected); err != nil || rejected["dispatchState"] != "notDispatched" || rejected["commitConfirmed"] == true || rejected["boundaryId"] != nil {
		t.Fatalf("unconfirmed callback returned commit evidence: %s %v", raw, err)
	}
}

func TestStopBoundaryToolUnavailableWithoutCallback(t *testing.T) {
	p, err := auth.NewPrincipal("fixture", "", "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), p)
	runtime, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("unavailable stop boundary dispatched input")
		return automation.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }})
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
		if tool.Name == "mechanize_state_stop_boundary" {
			t.Fatal("stop boundary advertised without callback")
		}
	}
	out, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_state_stop_boundary", Arguments: map[string]any{}})
	if err == nil && (out == nil || out.IsError == nil || !*out.IsError) {
		t.Fatal("unavailable stop boundary accepted")
	}
}
