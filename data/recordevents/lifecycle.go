package recordevents

import (
	context "context"
	"fmt"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// RecordedEventLifecycle customizes role Input.AppendRecordingEvents.
type RecordedEventLifecycle struct{}

func RecordedEventLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*RecordedEventLifecycle)(nil)).Elem()
}

var (
	RecordedEventLifecycleHooks = new(RecordedEventLifecycle)
	RecordedEventLifecycleDatly = RecordedEventLifecycleDatlyType()
)

func (hooks *RecordedEventLifecycle) Init(ctx context.Context, entity *RecordedEvent, state xhandler.LifecycleContext[RecordedEvent, xhandler.NoParent, AppendRecordingEventsOutput]) error {
	return nil
}
func (hooks *RecordedEventLifecycle) Validate(ctx context.Context, entity *RecordedEvent, state xhandler.LifecycleContext[RecordedEvent, xhandler.NoParent, AppendRecordingEventsOutput]) error {
	if entity.Namespace == nil {
		return fmt.Errorf("namespace required")
	}
	if _, err := data.RequireScope(ctx, *entity.Namespace); err != nil {
		return err
	}
	return nil
}
func (hooks *RecordedEventLifecycle) AfterSequence(ctx context.Context, entity *RecordedEvent, state xhandler.LifecycleContext[RecordedEvent, xhandler.NoParent, AppendRecordingEventsOutput]) error {
	return nil
}
func (hooks *RecordedEventLifecycle) AfterQueue(ctx context.Context, entity *RecordedEvent, state xhandler.LifecycleContext[RecordedEvent, xhandler.NoParent, AppendRecordingEventsOutput]) error {
	return nil
}
func (hooks *RecordedEventLifecycle) Finalize(ctx context.Context, input *AppendRecordingEventsInput, output *AppendRecordingEventsOutput, outcome xhandler.Outcome) error {
	return nil
}
