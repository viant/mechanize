package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

const completionRead = `let answer = app("com.example.Fixture").getById("result").read("staticText")`

func completionFixture(t *testing.T, execute automation.Execute, options automation.Options) (*ControllerDispatcher, chrome.ControllerIdentity, context.Context, string) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "completion", []string{"desktop:observe", "desktop:control"})
	p.ClientID = "controller:completion"
	ctx := auth.WithPrincipal(context.Background(), p)
	id := chrome.ControllerIdentity{Principal: p, ConversationID: "completion", Origin: "https://shell.fixture.test", DocumentID: "doc", CatalogToolLimit: 64}
	runtime, err := automation.NewWithOptions(execute, options)
	if err != nil {
		t.Fatal(err)
	}
	policy := script.Policy{AllowedSurfaces: map[string]bool{"com.example.Fixture": true}, AllowMutation: true, Capabilities: map[string]bool{"native:attributeRead": true, "native:idLocator": true, "native:semanticPress": true}}
	server, err := New(Dependencies{Runtime: runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return policy, nil }})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewControllerDispatcher(server, runtime)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		_ = dispatcher.CloseController(c, id)
	})
	session := controllerBody(t, controllerCall(t, dispatcher, ctx, id, "mechanize_session_open", map[string]any{}))["sessionId"].(string)
	return dispatcher, id, ctx, session
}
func completionOperation(t *testing.T, body any) Operation {
	t.Helper()
	raw, _ := json.Marshal(body)
	var op Operation
	if err := json.Unmarshal(raw, &op); err != nil {
		t.Fatal(err)
	}
	if op.ID == "" {
		t.Fatalf("missing operation: %s", raw)
	}
	return op
}
func completionArgs(session, request string, wait int) map[string]any {
	return map[string]any{"sessionId": session, "clientRequestId": request, "source": completionRead, "waitMs": wait, "outputBindings": []string{"answer"}}
}
func TestRunCompletionOneCallReturnsSafeOutputsAndSameRequestDoesNotReplay(t *testing.T) {
	var actions atomic.Int32
	d, id, ctx, session := completionFixture(t, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		actions.Add(1)
		time.Sleep(30 * time.Millisecond)
		v := model.Value{Kind: model.StringValue, String: "public fixture result"}
		return automation.StepResult{Value: &v}, nil
	}, automation.Options{})
	for _, tool := range []string{"mechanize_step_run", "mechanize_script_run"} {
		args := completionArgs(session, tool, 5000)
		result := controllerCall(t, d, ctx, id, tool, args)
		op := completionOperation(t, result.StructuredContent)
		if op.ExecutionStatus != "succeeded" || op.BusinessStatus != "unverified" || op.Outputs == nil || op.Outputs.Outputs["answer"].String != "public fixture result" || op.Outputs.Storage != "ephemeralRuntime" {
			t.Fatalf("completion unavailable: %+v", op)
		}
		count := actions.Load()
		args["waitMs"] = 0
		replay := completionOperation(t, controllerCall(t, d, ctx, id, tool, args).StructuredContent)
		if replay.ID != op.ID || replay.RunID != op.RunID || actions.Load() != count || replay.Outputs == nil {
			t.Fatal("response options changed request identity or repeated execution")
		}
	}
	// The old shape requires run + status + outputs. New shape above returns all
	// three projections in its original call; no polling/input dedup is involved.
	args := completionArgs(session, "legacy", 0)
	delete(args, "outputBindings")
	old := completionOperation(t, controllerCall(t, d, ctx, id, "mechanize_step_run", args).StructuredContent)
	if _, err := d.runtime.Wait(ctx, session, old.ID); err != nil {
		t.Fatal(err)
	}
	status := completionOperation(t, controllerCall(t, d, ctx, id, "mechanize_operation_status", map[string]any{"sessionId": session, "operationId": old.ID}).StructuredContent)
	output := controllerBody(t, controllerCall(t, d, ctx, id, "mechanize_operation_outputs", map[string]any{"sessionId": session, "operationId": old.ID, "bindings": []string{"answer"}}))
	if status.ExecutionStatus != "succeeded" || output["outputs"] == nil || actions.Load() != 3 {
		t.Fatal("legacy path no longer compatible")
	}
	t.Log("inert completion: 1 controller run call versus legacy run/status/outputs (3); executions once per original request")
}
func TestRunCompletionTimeoutAndRequestCancellationDoNotCancelExecution(t *testing.T) {
	for _, mode := range []string{"waitTimeout", "requestDeadlineReserve", "requestCanceled"} {
		t.Run(mode, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var actions atomic.Int32
			d, id, ctx, session := completionFixture(t, func(c context.Context, _ auth.Principal, _ model.Step, _ map[string]model.Value) (automation.StepResult, error) {
				actions.Add(1)
				close(entered)
				select {
				case <-release:
				case <-c.Done():
					return automation.StepResult{}, c.Err()
				}
				v := model.Value{Kind: model.StringValue, String: "later"}
				return automation.StepResult{Value: &v}, nil
			}, automation.Options{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			callCtx := ctx
			cancel := func() {}
			args := completionArgs(session, mode, 20)
			if mode == "requestDeadlineReserve" {
				callCtx, cancel = context.WithTimeout(ctx, 600*time.Millisecond)
				args["waitMs"] = 5000
			}
			if mode == "requestCanceled" {
				callCtx, cancel = context.WithCancel(ctx)
				args["waitMs"] = 5000
				go func() { <-entered; cancel() }()
			}
			defer cancel()
			started := time.Now()
			result := controllerCall(t, d, callCtx, id, "mechanize_step_run", args)
			if time.Since(started) > 400*time.Millisecond {
				t.Fatal("wait did not preserve reply deadline reserve")
			}
			var original Operation
			if mode != "requestCanceled" {
				original = completionOperation(t, result.StructuredContent)
				if original.ExecutionStatus == "succeeded" || original.Outputs != nil {
					t.Fatal("pending operation fabricated completion")
				}
			}
			close(release)
			args["waitMs"] = 5000
			completed := completionOperation(t, controllerCall(t, d, ctx, id, "mechanize_step_run", args).StructuredContent)
			if completed.ExecutionStatus != "succeeded" || completed.Outputs.Outputs["answer"].String != "later" || actions.Load() != 1 || original.ID != "" && original.ID != completed.ID {
				t.Fatal("observational cancellation replayed or cancelled action")
			}
		})
	}
}
func TestRunCompletionRejectsInvalidOutputsAndForeignOwnershipBeforeExecution(t *testing.T) {
	var actions atomic.Int32
	d, id, ctx, session := completionFixture(t, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		actions.Add(1)
		return automation.StepResult{}, nil
	}, automation.Options{})
	for _, patch := range []map[string]any{{"waitMs": -1}, {"waitMs": 5001}, {"waitMs": 1.5}, {"outputBindings": []string{"missing"}}, {"outputBindings": []string{"answer", "answer"}}, {"outputBindings": []string{"binding.answer"}}, {"extraOutput": "all"}} {
		args := completionArgs(session, "invalid", 1)
		for k, v := range patch {
			args[k] = v
		}
		r := controllerCall(t, d, ctx, id, "mechanize_step_run", args)
		if r.IsError == nil || !*r.IsError {
			t.Fatal("invalid response options admitted", patch)
		}
	}
	foreign := id
	foreign.Principal.ClientID = "controller:foreign"
	foreign.ConversationID = "foreign"
	r := controllerCall(t, d, auth.WithPrincipal(ctx, foreign.Principal), foreign, "mechanize_step_run", completionArgs(session, "foreign", 1))
	if r.IsError == nil || !*r.IsError {
		t.Fatal("foreign session admitted")
	}
	if actions.Load() != 0 {
		t.Fatal("invalid request reached executor")
	}
}
func TestRunCompletionPreservesFailureAndRedaction(t *testing.T) {
	for _, mode := range []string{"secret", "unknown", "objectiveFailed"} {
		t.Run(mode, func(t *testing.T) {
			options := automation.Options{}
			if mode == "objectiveFailed" {
				options.CompleteObjective = func(context.Context, auth.Principal, automation.CompletionRequest) (automation.BusinessResult, error) {
					return automation.BusinessResult{BusinessStatus: "failed", VerificationState: "unverified"}, nil
				}
			}
			d, id, ctx, session := completionFixture(t, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
				if mode == "unknown" {
					return automation.StepResult{DispatchState: "unknown", VerificationState: "unknown"}, errors.New("PRIVATE_ERROR_CANARY")
				}
				v := model.Value{Kind: model.ObjectValue, Object: map[string]model.Value{"password": {Kind: model.StringValue, String: "PRIVATE_VALUE_CANARY"}}}
				return automation.StepResult{Value: &v}, nil
			}, options)
			r := controllerCall(t, d, ctx, id, "mechanize_step_run", completionArgs(session, mode, 5000))
			op := completionOperation(t, r.StructuredContent)
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), "PRIVATE_") {
				t.Fatal("private output/error escaped")
			}
			if mode == "unknown" {
				if op.ExecutionStatus != "failed" || op.Outputs != nil {
					t.Fatal("uncertain error became success")
				}
			} else if op.Outputs == nil || len(op.Outputs.Outputs) != 0 || op.Outputs.Unavailable["answer"] == "" {
				t.Fatal("sensitive output not withheld")
			}
			if mode == "objectiveFailed" && op.BusinessStatus != "failed" {
				t.Fatal("execution replaced explicit objective result")
			}
		})
	}
}

func TestRunCompletionExplicitCancelRemainsCancelledWithoutOutputs(t *testing.T) {
	entered := make(chan struct{})
	var actions atomic.Int32
	d, id, ctx, session := completionFixture(t, func(c context.Context, _ auth.Principal, _ model.Step, _ map[string]model.Value) (automation.StepResult, error) {
		actions.Add(1)
		close(entered)
		<-c.Done()
		return automation.StepResult{DispatchState: "unknown", VerificationState: "unknown"}, c.Err()
	}, automation.Options{})
	args := completionArgs(session, "cancel-original", 0)
	started := completionOperation(t, controllerCall(t, d, ctx, id, "mechanize_step_run", args).StructuredContent)
	<-entered
	controllerCall(t, d, ctx, id, "mechanize_operation_cancel", map[string]any{"sessionId": session, "operationId": started.ID})
	args["waitMs"] = 5000
	final := completionOperation(t, controllerCall(t, d, ctx, id, "mechanize_step_run", args).StructuredContent)
	if final.ID != started.ID || final.ExecutionStatus != "cancelled" || final.Outputs != nil || actions.Load() != 1 {
		t.Fatalf("cancelled request changed: %+v calls%d", final, actions.Load())
	}
}

func TestRunCompletionWaitIncludesObjectiveButDoesNotInventCompletionAtBudget(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	options := automation.Options{CompleteObjective: func(context.Context, auth.Principal, automation.CompletionRequest) (automation.BusinessResult, error) {
		close(entered)
		<-release
		return automation.BusinessResult{BusinessStatus: "failed", VerificationState: "unverified"}, nil
	}}
	d, id, ctx, session := completionFixture(t, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		v := model.Value{Kind: model.StringValue, String: "observed"}
		return automation.StepResult{Value: &v}, nil
	}, options)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	args := completionArgs(session, "objective-pending", 60)
	pending := completionOperation(t, controllerCall(t, d, ctx, id, "mechanize_step_run", args).StructuredContent)
	if pending.ExecutionStatus != "succeeded" || pending.VerificationState != "pending" || pending.Outputs == nil {
		t.Fatalf("objective budget misrepresented: %+v", pending)
	}
	<-entered
	close(release)
	args["waitMs"] = 5000
	final := completionOperation(t, controllerCall(t, d, ctx, id, "mechanize_step_run", args).StructuredContent)
	if final.ID != pending.ID || final.BusinessStatus != "failed" {
		t.Fatal("explicit objective did not complete independently")
	}
}

func TestRunCompletionOptionsRemainClosedAndAdvertised(t *testing.T) {
	var input RunInput
	if json.Unmarshal([]byte(`{"sessionId":"s","clientRequestId":"r","source":"public","waitMs":5000,"outputBindings":["answer"],"readAll":true}`), &input) == nil {
		t.Fatal("canonical run silently accepted unknown field")
	}
	if err := json.Unmarshal([]byte(`{"sessionId":"s","clientRequestId":"r","source":"public","waitMs":5000,"outputBindings":["answer"]}`), &input); err != nil || input.WaitMs != 5000 {
		t.Fatal("accepted options failed", err)
	}
	d, id, ctx, _ := completionFixture(t, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("catalog executed an action")
		return automation.StepResult{}, nil
	}, automation.Options{})
	tools, err := d.ListTools(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mechanize_step_run", "mechanize_script_run"} {
		found := false
		for _, tool := range tools.Tools {
			if tool.Name == name {
				raw, _ := json.Marshal(tool.InputSchema)
				var schema map[string]any
				if json.Unmarshal(raw, &schema) != nil {
					t.Fatal("schema")
				}
				props := schema["properties"].(map[string]any)
				if props["waitMs"] == nil || props["outputBindings"] == nil {
					t.Fatal("options not discoverable", name)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("missing run tool", name)
		}
	}
}
