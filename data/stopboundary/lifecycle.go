package stopboundary

import (
	"context"
	"errors"
	"reflect"

	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
)

func same(p *string, v string) bool { return p != nil && *p == v }
func sameInt(p *int, v int) bool    { return p != nil && *p == v }
func validateEvent(e *Event, a data.StopBoundaryAuthority) error {
	if e == nil || !same(e.Namespace, a.Namespace) || !same(e.Id, a.AuditID) || !same(e.RunId, a.RunID) || e.AttemptId != nil || !sameInt(e.Sequence, a.AuditSequence) || !same(e.Kind, "stopped_boundary") || !same(e.PayloadJson, a.AuditPayloadJSON) || !same(e.CreatedAt, a.Now) {
		return errors.New("exact new immutable stopped-boundary audit required")
	}
	return nil
}

type RunLifecycle struct{}

func RunLifecycleDatlyType() reflect.Type { return reflect.TypeOf((*RunLifecycle)(nil)).Elem() }

var RunLifecycleHooks = new(RunLifecycle)
var RunLifecycleDatly = RunLifecycleDatlyType()

func (h *RunLifecycle) Init(ctx context.Context, r *Run, s xhandler.LifecycleContext[Run, xhandler.NoParent, StopBoundaryOutput]) error {
	if s.Previous != nil && s.Previous.Revision != nil {
		next := *s.Previous.Revision + 1
		r.SetRevision(&next)
	}
	return nil
}
func (h *RunLifecycle) Validate(ctx context.Context, r *Run, s xhandler.LifecycleContext[Run, xhandler.NoParent, StopBoundaryOutput]) error {
	a, err := data.RequireStopBoundaryAuthority(ctx)
	if err != nil {
		return err
	}
	p := s.Previous
	if p == nil || !same(p.Namespace, a.Namespace) || !same(p.Id, a.RunID) || !same(p.PlanId, a.PlanID) || !sameInt(p.Revision, a.RunRevision) || !sameInt(r.Revision, a.RunRevision+1) || !same(r.Status, "paused") || !same(r.UpdatedAt, a.Now) {
		return errors.New("owned exact stopped-boundary run CAS required")
	}
	if !same(p.EndlySessionId, a.EndlySessionID) || !same(p.EndlyOperationId, a.EndlyOperationID) {
		return errors.New("stopped-boundary persisted Endly correlation changed")
	}
	if p.Status == nil || (*p.Status != "running" && *p.Status != "paused" && *p.Status != "new") {
		return errors.New("terminal run cannot change stopped boundary")
	}
	if r.Has == nil || r.Has.PlanId || r.Has.CreatedAt || r.Has.EndlySessionId || r.Has.EndlyOperationId || len(r.Events) != 1 {
		return errors.New("stopped boundary cannot modify immutable run history or operation correlation")
	}
	max := 0
	for _, e := range p.Events {
		if e == nil || e.Sequence == nil {
			return errors.New("complete prior event cursor required")
		}
		if *e.Sequence > max {
			max = *e.Sequence
		}
		if same(e.Id, a.AuditID) {
			return errors.New("stopped-boundary audit already exists; adopt exact committed projection")
		}
	}
	if a.AuditSequence != max+1 {
		return errors.New("next immutable stopped-boundary audit cursor required")
	}
	return validateEvent(r.Events[0], a)
}
func (h *RunLifecycle) AfterSequence(context.Context, *Run, xhandler.LifecycleContext[Run, xhandler.NoParent, StopBoundaryOutput]) error {
	return nil
}
func (h *RunLifecycle) AfterQueue(context.Context, *Run, xhandler.LifecycleContext[Run, xhandler.NoParent, StopBoundaryOutput]) error {
	return nil
}
func (h *RunLifecycle) Finalize(context.Context, *StopBoundaryInput, *StopBoundaryOutput, xhandler.Outcome) error {
	return nil
}

type EventLifecycle struct{}

func EventLifecycleDatlyType() reflect.Type { return reflect.TypeOf((*EventLifecycle)(nil)).Elem() }

var EventLifecycleHooks = new(EventLifecycle)
var EventLifecycleDatly = EventLifecycleDatlyType()

func (h *EventLifecycle) Init(context.Context, *Event, xhandler.LifecycleContext[Event, Run, StopBoundaryOutput]) error {
	return nil
}
func (h *EventLifecycle) Validate(ctx context.Context, e *Event, s xhandler.LifecycleContext[Event, Run, StopBoundaryOutput]) error {
	a, err := data.RequireStopBoundaryAuthority(ctx)
	if err != nil {
		return err
	}
	if s.Previous != nil || s.Parent == nil || !same(s.Parent.Id, a.RunID) {
		return errors.New("stopped-boundary audit must be newly appended to exact parent")
	}
	return validateEvent(e, a)
}
func (h *EventLifecycle) AfterSequence(context.Context, *Event, xhandler.LifecycleContext[Event, Run, StopBoundaryOutput]) error {
	return nil
}
func (h *EventLifecycle) AfterQueue(context.Context, *Event, xhandler.LifecycleContext[Event, Run, StopBoundaryOutput]) error {
	return nil
}
