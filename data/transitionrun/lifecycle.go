package transitionrun

import (
	context "context"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// RunLifecycle customizes role Input.TransitionRun.
type RunLifecycle struct{}

func RunLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*RunLifecycle)(nil)).Elem()
}

var (
	RunLifecycleHooks = new(RunLifecycle)
	RunLifecycleDatly = RunLifecycleDatlyType()
)

func (hooks *RunLifecycle) Init(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, TransitionRunOutput]) error {
	if state.Previous != nil && state.Previous.Revision != nil {
		next := *state.Previous.Revision + 1
		entity.SetRevision(&next)
	}
	return nil
}
func (hooks *RunLifecycle) Validate(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, TransitionRunOutput]) error {
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

	if err := data.RequireStateMutationPermit(ctx, *entity.Namespace, *entity.Id); err != nil {
		return err
	}
	if len(state.Previous.Unresolved) > 0 {
		return fmt.Errorf("unresolved effects block safe run transition")
	}
	if entity.Status == nil || state.Previous.Status == nil {
		return fmt.Errorf("run transition state required")
	}
	if entity.Has.EndlySessionId || entity.Has.EndlyOperationId {
		return fmt.Errorf("transition cannot change operation correlation")
	}
	switch *entity.Status {
	case "paused", "succeeded", "failed", "cancelled":
	default:
		return fmt.Errorf("unsupported safe run transition")
	}
	switch *state.Previous.Status {
	case "new", "running", "paused":
	default:
		return fmt.Errorf("terminal run history is immutable")
	}
	if entity.Events[0].PayloadJson == nil {
		return fmt.Errorf("transition audit payload required")
	}
	var audit struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(*entity.Events[0].PayloadJson), &audit); err != nil || audit.Status != *entity.Status {
		return fmt.Errorf("transition audit payload mismatch")
	}
	if *entity.Status == "succeeded" {
		if state.Previous.PlanId == nil {
			return fmt.Errorf("immutable plan identity required")
		}
		if err := data.RequireBusinessVerification(ctx, *entity.Namespace, *entity.Id, *state.Previous.PlanId, *entity.Events[0].PayloadJson); err != nil {
			return err
		}
	}
	if entity.Events[0].Kind == nil || *entity.Events[0].Kind != "run_transition" {
		return fmt.Errorf("transition audit kind required")
	}

	return nil
}
func (hooks *RunLifecycle) AfterSequence(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, TransitionRunOutput]) error {
	return nil
}
func (hooks *RunLifecycle) AfterQueue(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, TransitionRunOutput]) error {
	return nil
}
func (hooks *RunLifecycle) Finalize(ctx context.Context, input *TransitionRunInput, output *TransitionRunOutput, outcome xhandler.Outcome) error {
	return nil
}
