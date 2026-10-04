package publishplan

import (
	context "context"
	"fmt"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// PlanRevisionLifecycle customizes role Input.PublishPlanRevision.
type PlanRevisionLifecycle struct{}

func PlanRevisionLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*PlanRevisionLifecycle)(nil)).Elem()
}

var (
	PlanRevisionLifecycleHooks = new(PlanRevisionLifecycle)
	PlanRevisionLifecycleDatly = PlanRevisionLifecycleDatlyType()
)

func (hooks *PlanRevisionLifecycle) Init(ctx context.Context, entity *PlanRevision, state xhandler.LifecycleContext[PlanRevision, xhandler.NoParent, PublishPlanRevisionOutput]) error {
	return nil
}
func (hooks *PlanRevisionLifecycle) Validate(ctx context.Context, entity *PlanRevision, state xhandler.LifecycleContext[PlanRevision, xhandler.NoParent, PublishPlanRevisionOutput]) error {
	if entity.Namespace == nil {
		return fmt.Errorf("namespace required")
	}
	if _, err := data.RequireScope(ctx, *entity.Namespace); err != nil {
		return err
	}
	return nil
}
func (hooks *PlanRevisionLifecycle) AfterSequence(ctx context.Context, entity *PlanRevision, state xhandler.LifecycleContext[PlanRevision, xhandler.NoParent, PublishPlanRevisionOutput]) error {
	return nil
}
func (hooks *PlanRevisionLifecycle) AfterQueue(ctx context.Context, entity *PlanRevision, state xhandler.LifecycleContext[PlanRevision, xhandler.NoParent, PublishPlanRevisionOutput]) error {
	return nil
}
func (hooks *PlanRevisionLifecycle) Finalize(ctx context.Context, input *PublishPlanRevisionInput, output *PublishPlanRevisionOutput, outcome xhandler.Outcome) error {
	return nil
}
