package beginattempt

import (
	context "context"
	"fmt"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// RunLifecycle customizes role Input.BeginAttempt.
type RunLifecycle struct{}

func RunLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*RunLifecycle)(nil)).Elem()
}

var (
	RunLifecycleHooks = new(RunLifecycle)
	RunLifecycleDatly = RunLifecycleDatlyType()
)

func (hooks *RunLifecycle) Init(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, BeginAttemptOutput]) error {
	if state.Previous != nil && state.Previous.Revision != nil {
		next := *state.Previous.Revision + 1
		entity.SetRevision(&next)
	}
	return nil
}
func (hooks *RunLifecycle) Validate(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, BeginAttemptOutput]) error {
	if entity.Namespace == nil || entity.Id == nil || *entity.Id == "" {
		return fmt.Errorf("complete scoped run identity required")
	}
	if _, err := data.RequireScope(ctx, *entity.Namespace); err != nil {
		return err
	}
	if state.Previous == nil {
		return fmt.Errorf("authorized run not found")
	}
	// Native Previous hydration can share the writable effects Current view
	// with this readonly auxiliary relation. Validate actual row state and scope
	// rather than assuming the filtered source alone excludes resolved history.
	for _, effect := range state.Previous.Unresolved {
		if effect == nil || effect.Namespace == nil || effect.RunId == nil || *effect.Namespace != *entity.Namespace || *effect.RunId != *entity.Id {
			return fmt.Errorf("effect history scope mismatch blocks dispatch")
		}
		if effect.State == nil {
			return fmt.Errorf("unresolved effect blocks dispatch")
		}
		switch *effect.State {
		case "confirmed", "absent": // resolved history, never a new pending intent
		default: // intent, unknown and unsupported states all remain barriers
			return fmt.Errorf("unresolved effect blocks dispatch")
		}
	}
	if entity.Has == nil || !entity.Has.Revision || entity.Revision == nil {
		return fmt.Errorf("run concurrency token required")
	}
	if len(entity.Attempts) != 1 {
		return fmt.Errorf("one attempt required")
	}
	if entity.PlanId != nil && state.Previous.PlanId != nil && *entity.PlanId != *state.Previous.PlanId {
		return fmt.Errorf("plan identity is immutable")
	}

	return nil
}
func (hooks *RunLifecycle) AfterSequence(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, BeginAttemptOutput]) error {
	return nil
}
func (hooks *RunLifecycle) AfterQueue(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, BeginAttemptOutput]) error {
	return nil
}
func (hooks *RunLifecycle) Finalize(ctx context.Context, input *BeginAttemptInput, output *BeginAttemptOutput, outcome xhandler.Outcome) error {
	return nil
}

// AttemptLifecycle customizes role Input.BeginAttempt.Attempts.
type AttemptLifecycle struct{}

func AttemptLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*AttemptLifecycle)(nil)).Elem()
}

var (
	AttemptLifecycleHooks = new(AttemptLifecycle)
	AttemptLifecycleDatly = AttemptLifecycleDatlyType()
)

func (hooks *AttemptLifecycle) Init(ctx context.Context, entity *Attempt, state xhandler.LifecycleContext[Attempt, Run, BeginAttemptOutput]) error {
	return nil
}
func (hooks *AttemptLifecycle) Validate(ctx context.Context, entity *Attempt, state xhandler.LifecycleContext[Attempt, Run, BeginAttemptOutput]) error {
	if entity.Namespace == nil {
		return fmt.Errorf("namespace required")
	}
	scope, err := data.RequireScope(ctx, *entity.Namespace)
	if err != nil {
		return err
	}
	if state.Previous != nil {
		return fmt.Errorf("attempt already exists; reconcile before dispatch")
	}
	if entity.LeaseEpoch == nil || scope.LeaseEpoch <= 0 || *entity.LeaseEpoch != scope.LeaseEpoch {
		return fmt.Errorf("desktop lease epoch mismatch")
	}
	if entity.State == nil || *entity.State != "intent" || len(entity.Intents) != 1 || len(entity.Events) != 1 {
		return fmt.Errorf("one committed intent and audit event required")
	}
	if entity.Intents[0].State == nil || *entity.Intents[0].State != "intent" {
		return fmt.Errorf("intent state required")
	}

	return nil
}
func (hooks *AttemptLifecycle) AfterSequence(ctx context.Context, entity *Attempt, state xhandler.LifecycleContext[Attempt, Run, BeginAttemptOutput]) error {
	return nil
}
func (hooks *AttemptLifecycle) AfterQueue(ctx context.Context, entity *Attempt, state xhandler.LifecycleContext[Attempt, Run, BeginAttemptOutput]) error {
	return nil
}
