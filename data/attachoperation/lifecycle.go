package attachoperation

import (
	context "context"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// RunLifecycle customizes role Input.AttachOperation.
type RunLifecycle struct{}

func RunLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*RunLifecycle)(nil)).Elem()
}

var (
	RunLifecycleHooks = new(RunLifecycle)
	RunLifecycleDatly = RunLifecycleDatlyType()
)

func (hooks *RunLifecycle) Init(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, AttachOperationOutput]) error {
	if state.Previous != nil && state.Previous.Revision != nil {
		next := *state.Previous.Revision + 1
		entity.SetRevision(&next)
	}
	return nil
}
func (hooks *RunLifecycle) Validate(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, AttachOperationOutput]) error {
	if entity.Namespace == nil || entity.Id == nil {
		return fmt.Errorf("scoped identity required")
	}
	if _, err := data.RequireScope(ctx, *entity.Namespace); err != nil {
		return err
	}

	if state.Previous == nil {
		return fmt.Errorf("authorized run not found")
	}
	if len(entity.Events) != 1 || entity.Events[0].Id == nil {
		return fmt.Errorf("one new audit event required")
	}
	for _, previous := range state.Previous.Events {
		if previous.Id != nil && *previous.Id == *entity.Events[0].Id {
			return fmt.Errorf("audit history is immutable")
		}
	}
	if entity.Has.PlanId || entity.Has.CreatedAt {
		return fmt.Errorf("run objective and creation history are immutable")
	}

	resume := state.Previous.Revision != nil && data.RequireResumePermit(ctx, *entity.Namespace, *entity.Id, *state.Previous.Revision) == nil
	if resume {
		if state.Previous.Status == nil || (*state.Previous.Status != "running" && *state.Previous.Status != "paused") {
			return fmt.Errorf("run is not resumable")
		}
		if len(state.Previous.Unresolved) > 0 {
			return fmt.Errorf("unresolved effects block resume correlation")
		}
		if !entity.Has.Status || entity.Status == nil || *entity.Status != "running" {
			return fmt.Errorf("resume must atomically publish running status")
		}
	} else if entity.Has.Status {
		return fmt.Errorf("correlation cannot change run status")
	}
	if entity.EndlySessionId == nil || entity.EndlyOperationId == nil || *entity.EndlySessionId == "" || *entity.EndlyOperationId == "" {
		return fmt.Errorf("complete operation correlation required")
	}
	if !resume && state.Previous.EndlySessionId != nil && *state.Previous.EndlySessionId != "" && *entity.EndlySessionId != *state.Previous.EndlySessionId {
		return fmt.Errorf("run session correlation is immutable")
	}
	if !resume && state.Previous.EndlyOperationId != nil && *state.Previous.EndlyOperationId != "" && *entity.EndlyOperationId != *state.Previous.EndlyOperationId {
		return fmt.Errorf("run operation correlation is immutable")
	}
	if entity.Events[0].PayloadJson == nil {
		return fmt.Errorf("correlation audit payload required")
	}
	var audit struct {
		SessionID   string `json:"sessionId"`
		OperationID string `json:"operationId"`
	}
	if err := json.Unmarshal([]byte(*entity.Events[0].PayloadJson), &audit); err != nil || audit.SessionID != *entity.EndlySessionId || audit.OperationID != *entity.EndlyOperationId {
		return fmt.Errorf("correlation audit payload mismatch")
	}
	expectedKind := "operation_attached"
	if resume {
		expectedKind = "operation_resumed"
	}
	if entity.Events[0].Kind == nil || *entity.Events[0].Kind != expectedKind {
		return fmt.Errorf("correlation audit kind required")
	}

	return nil
}
func (hooks *RunLifecycle) AfterSequence(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, AttachOperationOutput]) error {
	return nil
}
func (hooks *RunLifecycle) AfterQueue(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, AttachOperationOutput]) error {
	return nil
}
func (hooks *RunLifecycle) Finalize(ctx context.Context, input *AttachOperationInput, output *AttachOperationOutput, outcome xhandler.Outcome) error {
	return nil
}
