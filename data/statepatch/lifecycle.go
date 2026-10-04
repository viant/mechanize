package statepatch

import (
	context "context"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
	"regexp"
)

// RunStateLifecycle customizes role Input.StatePatch.
type RunStateLifecycle struct{}

func RunStateLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*RunStateLifecycle)(nil)).Elem()
}

var (
	RunStateLifecycleHooks = new(RunStateLifecycle)
	RunStateLifecycleDatly = RunStateLifecycleDatlyType()
)

func (hooks *RunStateLifecycle) Init(ctx context.Context, entity *RunState, state xhandler.LifecycleContext[RunState, xhandler.NoParent, StatePatchOutput]) error {
	if state.Previous != nil && state.Previous.Revision != nil {
		next := *state.Previous.Revision + 1
		entity.SetRevision(&next)
	}
	return nil
}
func (hooks *RunStateLifecycle) Validate(ctx context.Context, entity *RunState, state xhandler.LifecycleContext[RunState, xhandler.NoParent, StatePatchOutput]) error {
	if entity.Namespace == nil || entity.Id == nil {
		return fmt.Errorf("complete scoped identity required")
	}
	if err := data.RequireStateMutationPermit(ctx, *entity.Namespace, *entity.Id); err != nil {
		return err
	}
	if state.Previous == nil {
		return fmt.Errorf("authorized state run not found")
	}
	if state.Previous.Status == nil || (*state.Previous.Status != "new" && *state.Previous.Status != "paused") {
		return fmt.Errorf("state mutation requires new or paused run")
	}
	if len(state.Previous.Unresolved) > 0 {
		return fmt.Errorf("unresolved effect blocks state mutation")
	}
	if entity.Has == nil || !entity.Has.Revision || entity.Revision == nil {
		return fmt.Errorf("expected run revision required")
	}
	if entity.Has.Status {
		return fmt.Errorf("state patch cannot change run lifecycle status")
	}
	if len(entity.Variables) == 0 || len(entity.Variables) > 128 {
		return fmt.Errorf("state patch must contain 1...128 variables")
	}

	return nil
}
func (hooks *RunStateLifecycle) AfterSequence(ctx context.Context, entity *RunState, state xhandler.LifecycleContext[RunState, xhandler.NoParent, StatePatchOutput]) error {
	return nil
}
func (hooks *RunStateLifecycle) AfterQueue(ctx context.Context, entity *RunState, state xhandler.LifecycleContext[RunState, xhandler.NoParent, StatePatchOutput]) error {
	return nil
}
func (hooks *RunStateLifecycle) Finalize(ctx context.Context, input *StatePatchInput, output *StatePatchOutput, outcome xhandler.Outcome) error {
	return nil
}

// VariableLifecycle customizes role Input.StatePatch.Variables.
type VariableLifecycle struct{}

func VariableLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*VariableLifecycle)(nil)).Elem()
}

var (
	VariableLifecycleHooks = new(VariableLifecycle)
	VariableLifecycleDatly = VariableLifecycleDatlyType()
)

func (hooks *VariableLifecycle) Init(ctx context.Context, entity *Variable, state xhandler.LifecycleContext[Variable, RunState, StatePatchOutput]) error {
	return nil
}
func (hooks *VariableLifecycle) Validate(ctx context.Context, entity *Variable, state xhandler.LifecycleContext[Variable, RunState, StatePatchOutput]) error {
	if entity.Namespace == nil || entity.RunId == nil {
		return fmt.Errorf("variable parent identity required")
	}
	if err := data.RequireStateMutationPermit(ctx, *entity.Namespace, *entity.RunId); err != nil {
		return err
	}
	if entity.Name == nil || !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`).MatchString(*entity.Name) {
		return fmt.Errorf("invalid user variable name")
	}
	if entity.ValueJson == nil || len(*entity.ValueJson) > 65536 {
		return fmt.Errorf("bounded typed variable value required")
	}
	var value model.Value
	if err := json.Unmarshal([]byte(*entity.ValueJson), &value); err != nil {
		return fmt.Errorf("invalid typed variable JSON")
	}
	if err := value.Validate(); err != nil {
		return err
	}

	return nil
}
func (hooks *VariableLifecycle) AfterSequence(ctx context.Context, entity *Variable, state xhandler.LifecycleContext[Variable, RunState, StatePatchOutput]) error {
	return nil
}
func (hooks *VariableLifecycle) AfterQueue(ctx context.Context, entity *Variable, state xhandler.LifecycleContext[Variable, RunState, StatePatchOutput]) error {
	return nil
}
