package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestMCPResumeUsesApprovedOwnedSession(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
	p.ClientID, p.ClientName = "fixture-agent", "Fixture Agent"
	ctx := auth.WithPrincipal(context.Background(), p)
	plan, err := script.Compile(`app("fixture.app").getById("first").read("text"); app("fixture.app").getById("second").read("text")`)
	if err != nil {
		t.Fatal(err)
	}
	var admitted atomic.Bool
	var dispatched atomic.Int32
	runtime, err := automation.NewWithOptions(func(ctx context.Context, actual auth.Principal, step model.Step, _ map[string]model.Value) (automation.StepResult, error) {
		binding, ok := auth.ConsentBindingFromContext(ctx)
		metadata, _ := automation.ExecutionFromContext(ctx)
		if !admitted.Load() || !ok || binding.GrantID != "approved-fixture-grant" || binding.SessionID != metadata.SessionID || binding.Purpose != "Continue fixture" || actual.ClientID != p.ClientID || metadata.StepIndex != 1 || step.ID != plan.Steps[1].ID {
			return automation.StepResult{}, errors.New("resumed dispatch lost admission, consent or original step identity")
		}
		dispatched.Add(1)
		return automation.StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
	}, automation.Options{LoadResume: func(context.Context, auth.Principal, string, int, string, string) (automation.ResumeSnapshot, error) {
		return automation.ResumeSnapshot{RunID: "run-1", PlanID: "plan-1", ObjectiveID: "objective-1", Revision: 3, Status: "paused", Plan: *plan, Completed: map[string]automation.StepResult{plan.Steps[0].ID: {DispatchState: "notDispatched", VerificationState: "verified"}}}, nil
	}, AttachOperation: func(context.Context, auth.Principal, string, int, string, string) error {
		admitted.Store(true)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtime.Open(ctx, "resume fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx, session.SessionID)
	var calls atomic.Int32
	server, err := New(Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, StateResume: func(ctx context.Context, actual auth.Principal, sessionID, runID string, revision int, planID, objectiveID string) (*automation.ResumeResult, error) {
		calls.Add(1)
		return runtime.ResumeInSession(ctx, actual, sessionID, runID, revision, planID, objectiveID)
	}})
	if err != nil {
		t.Fatal(err)
	}
	client := server.AsClient(ctx)
	if _, err = client.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"sessionId": session.SessionID, "runId": "run-1", "expectedRevision": 3, "expectedPlanId": "plan-1", "expectedObjectiveId": "objective-1", "purpose": "Continue fixture"}
	rejected, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_state_resume", Arguments: args})
	if err != nil || rejected.IsError == nil || !*rejected.IsError || calls.Load() != 0 {
		t.Fatalf("missing grant admitted: %+v %v", rejected, err)
	}
	args["grantId"] = "approved-fixture-grant"
	args["expectedRevision"] = 2
	rejected, err = client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_state_resume", Arguments: args})
	if err != nil || rejected.IsError == nil || !*rejected.IsError || dispatched.Load() != 0 {
		t.Fatalf("stale revision admitted: %+v %v", rejected, err)
	}
	args["expectedRevision"] = 3
	started, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_state_resume", Arguments: args})
	if err != nil || started.IsError != nil && *started.IsError {
		t.Fatalf("resume: %+v %v", started, err)
	}
	encoded, _ := json.Marshal(started.StructuredContent)
	var operation Operation
	if err = json.Unmarshal(encoded, &operation); err != nil {
		t.Fatal(err)
	}
	if operation.SessionID != session.SessionID || operation.RunID != "run-1" || operation.ID == "" {
		t.Fatalf("resume changed operation identity: %+v", operation)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = runtime.Wait(wait, session.SessionID, operation.ID); err != nil {
		t.Fatal(err)
	}
	status, err := runtime.Status(ctx, session.SessionID, operation.ID)
	if err != nil || status.Status != "succeeded" || dispatched.Load() != 1 {
		t.Fatalf("resume execution: %+v dispatches=%d %v", status, dispatched.Load(), err)
	}
	other := p
	other.ClientID = "other-agent"
	foreign := auth.WithPrincipal(context.Background(), other)
	denied, err := client.CallTool(foreign, &schema.CallToolRequestParams{Name: "mechanize_state_resume", Arguments: args})
	if err != nil || denied.IsError == nil || !*denied.IsError || dispatched.Load() != 1 {
		t.Fatalf("foreign client admitted: %+v %v", denied, err)
	}
}
