package createrun

import (
	context "context"
	"fmt"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// RunLifecycle customizes role Input.CreateRun.
type RunLifecycle struct{}

func RunLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*RunLifecycle)(nil)).Elem()
}

var (
	RunLifecycleHooks = new(RunLifecycle)
	RunLifecycleDatly = RunLifecycleDatlyType()
)

func (hooks *RunLifecycle) Init(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, CreateRunOutput]) error {
	return nil
}
func (hooks *RunLifecycle) Validate(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, CreateRunOutput]) error {
	if entity.Namespace == nil {
		return fmt.Errorf("namespace required")
	}
	if _, err := data.RequireScope(ctx, *entity.Namespace); err != nil {
		return err
	}
	return nil
}
func (hooks *RunLifecycle) AfterSequence(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, CreateRunOutput]) error {
	return nil
}
func (hooks *RunLifecycle) AfterQueue(ctx context.Context, entity *Run, state xhandler.LifecycleContext[Run, xhandler.NoParent, CreateRunOutput]) error {
	return nil
}
func (hooks *RunLifecycle) Finalize(ctx context.Context, input *CreateRunInput, output *CreateRunOutput, outcome xhandler.Outcome) error {
	return nil
}
