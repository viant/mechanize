package consentcreate

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	"reflect"
)

type RecordLifecycle struct{}

func RecordLifecycleDatlyType() reflect.Type { return reflect.TypeOf((*RecordLifecycle)(nil)).Elem() }

var RecordLifecycleHooks = new(RecordLifecycle)
var RecordLifecycleDatly = RecordLifecycleDatlyType()

func (hooks *RecordLifecycle) Init(ctx context.Context, entity *Record, state xhandler.LifecycleContext[Record, xhandler.NoParent, CreateRequestOutput]) error {
	if state.Previous != nil && state.Previous.Revision != nil {
		n := *state.Previous.Revision + 1
		entity.SetRevision(&n)
	}
	return nil
}
func (hooks *RecordLifecycle) Validate(ctx context.Context, entity *Record, state xhandler.LifecycleContext[Record, xhandler.NoParent, CreateRequestOutput]) error {
	if entity.Namespace == nil || entity.Id == nil {
		return fmt.Errorf("consent identity required")
	}
	if _, err := data.RequireScope(ctx, *entity.Namespace); err != nil {
		return err
	}
	raw, err := json.Marshal(entity)
	if err != nil {
		return err
	}
	var previous []byte
	if state.Previous != nil {
		previous, err = json.Marshal(state.Previous)
		if err != nil {
			return err
		}
	}
	if len(entity.Audit) != 1 {
		return fmt.Errorf("exactly one immutable consent audit required")
	}
	a := entity.Audit[0]
	if a.Id == nil || a.ActorId == nil || a.Kind == nil || a.CreatedAt == nil || a.PayloadJson == nil {
		return fmt.Errorf("consent audit fields required")
	}
	if state.Previous != nil {
		for _, old := range state.Previous.Audit {
			if old.Id != nil && *old.Id == *a.Id {
				return fmt.Errorf("consent audit history is immutable")
			}
		}
	}
	return data.ValidateConsentMutation(ctx, "create", raw, previous, *a.Id, *a.ActorId, *a.Kind, *a.CreatedAt, *a.PayloadJson)
}
func (hooks *RecordLifecycle) AfterSequence(ctx context.Context, entity *Record, state xhandler.LifecycleContext[Record, xhandler.NoParent, CreateRequestOutput]) error {
	return nil
}
func (hooks *RecordLifecycle) AfterQueue(ctx context.Context, entity *Record, state xhandler.LifecycleContext[Record, xhandler.NoParent, CreateRequestOutput]) error {
	return nil
}
func (hooks *RecordLifecycle) Finalize(ctx context.Context, input *CreateRequestInput, output *CreateRequestOutput, outcome xhandler.Outcome) error {
	return nil
}
