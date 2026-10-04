package endly

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestInitialOperationCorrelationGatesInput(t *testing.T) {
	for _, scenario := range []string{"committed", "attach_failure", "request_cancelled", "request_cancelled_nil", "operation_cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			owner := actor(t, "alice")
			principal, _ := auth.FromContext(owner)
			principal.ClientID, principal.ClientName = "client-a", "Fixture Agent"
			owner = auth.WithPrincipal(owner, principal)
			plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
			if err != nil {
				t.Fatal(err)
			}
			inputs := map[string]model.Value{"label": {Kind: model.StringValue, String: "fixture"}}
			type correlation struct{ run, session, operation string }
			attached := make(chan correlation, 1)
			release := make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			var preparations, attachments, dispatches atomic.Int32
			var committed atomic.Bool
			var sessionID, preparedRun string
			executed := make(chan ExecutionMetadata, 1)
			r, err := NewWithOptions(func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (StepResult, error) {
				dispatches.Add(1)
				meta, ok := ExecutionFromContext(ctx)
				executed <- meta
				binding, bound := auth.ConsentBindingFromContext(ctx)
				if !committed.Load() || !ok || !reflect.DeepEqual(p, principal) || step.ID != plan.Steps[0].ID || !reflect.DeepEqual(values["input.label"], inputs["label"]) || !bound || binding != (auth.ConsentBinding{SessionID: sessionID, GrantID: "grant", Purpose: "Save fixture"}) {
					return StepResult{}, errors.New("input lost committed correlation, principal, plan, values or consent")
				}
				return StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
			}, Options{PreparePlan: func(ctx context.Context, p auth.Principal, run, session string, actual model.Plan, values map[string]model.Value) (string, error) {
				preparations.Add(1)
				if !reflect.DeepEqual(p, principal) || session != sessionID || run == "" || !reflect.DeepEqual(actual, *plan) || !reflect.DeepEqual(values, inputs) {
					return "", errors.New("durable preparation lost exact request")
				}
				preparedRun = run
				return "prepared-plan", nil
			}, AttachInitialOperation: func(ctx context.Context, p auth.Principal, run string, revision int, session, operation string) error {
				attachments.Add(1)
				if !reflect.DeepEqual(p, principal) || run != preparedRun || session != sessionID || operation == "" || revision != 1 {
					return errors.New("initial correlation lost principal, run, revision or operation")
				}
				attached <- correlation{run: run, session: session, operation: operation}
				<-release
				if scenario == "attach_failure" {
					return errors.New("correlation commit unavailable")
				}
				if scenario == "request_cancelled_nil" {
					return nil
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				committed.Store(true)
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			session, err := r.Open(owner, "initial operation")
			if err != nil {
				t.Fatal(err)
			}
			sessionID = session.SessionID
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
				_ = r.Close(owner, sessionID)
			}()
			ctx := auth.WithConsentBinding(owner, auth.ConsentBinding{SessionID: sessionID, GrantID: "grant", Purpose: "Save fixture"})
			startCtx, cancelStart := context.WithCancel(ctx)
			defer cancelStart()
			type startResult struct {
				operation *manager.Operation
				err       error
			}
			started := make(chan startResult, 1)
			go func() {
				op, err := r.StartPlanWithRequest(startCtx, sessionID, "stable-request", *plan, inputs)
				started <- startResult{operation: op, err: err}
			}()
			var correlated correlation
			select {
			case correlated = <-attached:
			case result := <-started:
				t.Fatalf("start returned before correlation: %+v", result)
			case <-time.After(5 * time.Second):
				t.Fatal("initial correlation callback not reached")
			}
			select {
			case meta := <-executed:
				t.Fatalf("input executed before correlation committed: %+v", meta)
			case <-time.After(50 * time.Millisecond):
			}
			if scenario == "request_cancelled" || scenario == "request_cancelled_nil" {
				cancelStart()
			}
			if scenario == "operation_cancelled" {
				if _, err = r.Cancel(owner, sessionID, correlated.operation); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			var result startResult
			select {
			case result = <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("start did not finish after correlation callback")
			}
			if scenario == "attach_failure" || scenario == "request_cancelled" || scenario == "request_cancelled_nil" {
				if result.err == nil {
					t.Fatal("uncommitted correlation admitted")
				}
			} else if result.err != nil || result.operation == nil || result.operation.ID != correlated.operation {
				t.Fatalf("admitted operation correlation changed: %+v", result)
			}
			wait, cancelWait := context.WithTimeout(owner, 5*time.Second)
			defer cancelWait()
			finished, err := r.Wait(wait, sessionID, correlated.operation)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "committed" {
				if finished.Status != manager.OperationSucceeded || dispatches.Load() != 1 {
					t.Fatalf("committed operation failed: %+v dispatches=%d", finished, dispatches.Load())
				}
				meta := <-executed
				if meta != (ExecutionMetadata{RunID: correlated.run, PlanID: "prepared-plan", SessionID: sessionID, OperationID: correlated.operation, StepIndex: 0}) {
					t.Fatalf("initial execute metadata lost correlation: %+v", meta)
				}
			} else if dispatches.Load() != 0 || finished.Status == manager.OperationSucceeded {
				t.Fatalf("failed/cancelled admission dispatched: %+v dispatches=%d", finished, dispatches.Load())
			}
			// A replay must retain the inhibited original operation after failure
			// or cancellation; it must not prepare, attach or execute fresh input.
			for i := 0; i < 2; i++ {
				op, err := r.StartPlanWithRequest(ctx, sessionID, "stable-request", *plan, inputs)
				if err == nil && (op == nil || op.ID != correlated.operation) {
					t.Fatalf("same request replaced original operation: %+v", op)
				}
			}
			wantDispatches := int32(0)
			if scenario == "committed" {
				wantDispatches = 1
			}
			if preparations.Load() != 1 || attachments.Load() != 1 || dispatches.Load() != wantDispatches {
				t.Fatalf("same request replayed admission/input: prepares=%d attaches=%d dispatches=%d", preparations.Load(), attachments.Load(), dispatches.Load())
			}
		})
	}
}

func TestInitialOperationCorrelationRequiresPreparation(t *testing.T) {
	var calls atomic.Int32
	r, err := NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		calls.Add(1)
		return StepResult{}, nil
	}, Options{AttachInitialOperation: func(context.Context, auth.Principal, string, int, string, string) error {
		calls.Add(1)
		return nil
	}})
	if err == nil || r != nil || calls.Load() != 0 {
		t.Fatalf("correlation without durable preparation accepted: runtime=%v err=%v calls=%d", r, err, calls.Load())
	}
}
