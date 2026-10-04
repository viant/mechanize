package commitoutcome

import (
	context "context"
	"fmt"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// EffectLifecycle customizes role Input.CommitOutcome.
type EffectLifecycle struct{}

func EffectLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*EffectLifecycle)(nil)).Elem()
}

var (
	EffectLifecycleHooks = new(EffectLifecycle)
	EffectLifecycleDatly = EffectLifecycleDatlyType()
)

func (hooks *EffectLifecycle) Init(ctx context.Context, entity *Effect, state xhandler.LifecycleContext[Effect, xhandler.NoParent, CommitOutcomeOutput]) error {
	if state.Previous != nil && state.Previous.Revision != nil {
		next := *state.Previous.Revision + 1
		entity.SetRevision(&next)
	}
	return nil
}
func (hooks *EffectLifecycle) Validate(ctx context.Context, entity *Effect, state xhandler.LifecycleContext[Effect, xhandler.NoParent, CommitOutcomeOutput]) error {
	if entity.Namespace == nil {
		return fmt.Errorf("namespace required")
	}
	if _, err := data.RequireScope(ctx, *entity.Namespace); err != nil {
		return err
	}
	if state.Previous == nil {
		return fmt.Errorf("authorized effect not found")
	}
	if entity.Has == nil || !entity.Has.Revision || entity.Revision == nil {
		return fmt.Errorf("effect concurrency token required")
	}
	if entity.AttemptId == nil || state.Previous.AttemptId == nil || *entity.AttemptId != *state.Previous.AttemptId {
		return fmt.Errorf("attempt identity is immutable")
	}
	if entity.RunId == nil || state.Previous.RunId == nil || *entity.RunId != *state.Previous.RunId {
		return fmt.Errorf("run identity is immutable")
	}
	if entity.BusinessKey != nil && state.Previous.BusinessKey != nil && *entity.BusinessKey != *state.Previous.BusinessKey {
		return fmt.Errorf("business identity is immutable")
	}
	if entity.State == nil {
		return fmt.Errorf("outcome state required")
	}
	switch *entity.State {
	case "confirmed", "absent", "unknown":
	default:
		return fmt.Errorf("invalid outcome state")
	}
	if state.Previous.State == nil || (*state.Previous.State != "intent" && *state.Previous.State != "unknown") {
		return fmt.Errorf("effect already resolved")
	}
	if len(entity.Events) != 1 {
		return fmt.Errorf("outcome audit event required")
	}

	return nil
}
func (hooks *EffectLifecycle) AfterSequence(ctx context.Context, entity *Effect, state xhandler.LifecycleContext[Effect, xhandler.NoParent, CommitOutcomeOutput]) error {
	return nil
}
func (hooks *EffectLifecycle) AfterQueue(ctx context.Context, entity *Effect, state xhandler.LifecycleContext[Effect, xhandler.NoParent, CommitOutcomeOutput]) error {
	return nil
}
func (hooks *EffectLifecycle) Finalize(ctx context.Context, input *CommitOutcomeInput, output *CommitOutcomeOutput, outcome xhandler.Outcome) error {
	return nil
}
