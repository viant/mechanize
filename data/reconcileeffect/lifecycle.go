package reconcileeffect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
	xhandler "github.com/viant/xdatly/handler"
	"reflect"
)

func same(p *string, v string) bool { return p != nil && *p == v }
func sameInt(p *int, v int) bool    { return p != nil && *p == v }
func validateMilestone(m *Milestone, a data.ReconcileEffectAuthority) error {
	if m == nil || !same(m.Namespace, a.Namespace) || !same(m.Id, a.MilestoneID) || !same(m.RunId, a.RunID) || !same(m.AttemptId, a.AttemptID) || !same(m.State, "verified") || !same(m.EvidenceJson, a.EvidenceJSON) {
		return errors.New("exact verified reconciliation milestone required")
	}
	return nil
}
func validateEvent(e *Event, a data.ReconcileEffectAuthority) error {
	if e == nil || !same(e.Namespace, a.Namespace) || !same(e.Id, a.AuditID) || !same(e.RunId, a.RunID) || !same(e.AttemptId, a.AttemptID) || !sameInt(e.Sequence, a.AuditSequence) || !same(e.Kind, "effect_reconciliation") || !same(e.PayloadJson, a.AuditPayloadJSON) || !same(e.CreatedAt, a.Now) {
		return errors.New("exact immutable reconciliation audit required")
	}
	return nil
}

type RunLifecycle struct{}

func RunLifecycleDatlyType() reflect.Type { return reflect.TypeOf((*RunLifecycle)(nil)).Elem() }

var RunLifecycleHooks = new(RunLifecycle)
var RunLifecycleDatly = RunLifecycleDatlyType()

func (h *RunLifecycle) Init(ctx context.Context, r *Run, s xhandler.LifecycleContext[Run, xhandler.NoParent, ReconcileEffectOutput]) error {
	if s.Previous != nil && s.Previous.Revision != nil {
		next := *s.Previous.Revision + 1
		r.SetRevision(&next)
	}
	return nil
}
func (h *RunLifecycle) Validate(ctx context.Context, r *Run, s xhandler.LifecycleContext[Run, xhandler.NoParent, ReconcileEffectOutput]) error {
	a, err := data.RequireReconcileEffectAuthority(ctx)
	if err != nil {
		return err
	}
	p := s.Previous
	if p == nil || !same(p.Namespace, a.Namespace) || !same(p.Id, a.RunID) || !same(p.PlanId, a.PlanID) || !sameInt(p.Revision, a.RunRevision) || !sameInt(r.Revision, a.RunRevision+1) || !same(r.Status, "paused") || !same(r.UpdatedAt, a.Now) {
		return errors.New("owned current run reconciliation CAS required")
	}
	if p.Status == nil || (*p.Status != "running" && *p.Status != "paused" && *p.Status != "new") {
		return errors.New("terminal run cannot adopt effect evidence")
	}
	if r.Has == nil || r.Has.PlanId || r.Has.CreatedAt || r.Has.EndlySessionId || r.Has.EndlyOperationId || len(r.Effects) != 1 || len(r.Events) != 1 {
		return errors.New("reconciliation cannot change run history or operation correlation")
	}
	canonicalAttempt := a.AttemptID == data.ReconcileEffectKey("attempt", a.RunID, a.PlanID, a.StepID)
	if !canonicalAttempt && p.EndlySessionId != nil && *p.EndlySessionId != "" && p.EndlyOperationId != nil && *p.EndlyOperationId != "" {
		// Resumed attempts are fenced by the persisted admitted operation, never
		// an operation ID supplied in the reconciliation body or proof.
		canonicalAttempt = a.AttemptID == data.ReconcileEffectKey("attempt-resume", a.RunID, a.PlanID, a.StepID, *p.EndlyOperationId)
	}
	if !canonicalAttempt || a.EffectID != data.ReconcileEffectKey("effect", a.AttemptID) || a.MilestoneID != data.ReconcileEffectKey("milestone", a.RunID, a.StepID) {
		return errors.New("canonical original attempt/effect/milestone correlation required")
	}
	var attempt *OriginalAttempt
	for _, v := range p.Attempts {
		if v != nil && same(v.Id, a.AttemptID) {
			if attempt != nil {
				return errors.New("duplicate original attempt")
			}
			attempt = v
		}
	}
	if attempt == nil || !same(attempt.Namespace, a.Namespace) || !same(attempt.RunId, a.RunID) || !same(attempt.PlanId, a.PlanID) || !same(attempt.StepId, a.StepID) {
		return errors.New("original immutable attempt correlation mismatch")
	}
	var plan *OriginalPlan
	for _, v := range p.Plans {
		if v != nil && same(v.Id, a.PlanID) {
			if plan != nil {
				return errors.New("duplicate original plan")
			}
			plan = v
		}
	}
	if plan == nil || !same(plan.Namespace, a.Namespace) || plan.ContentJson == nil || plan.ContentHash == nil || data.ReconcileEffectHash([]byte(*plan.ContentJson)) != *plan.ContentHash {
		return errors.New("original immutable plan hash unavailable")
	}
	var envelope struct {
		Plan model.Plan `json:"plan"`
	}
	if json.Unmarshal([]byte(*plan.ContentJson), &envelope) != nil {
		return errors.New("original plan envelope unavailable")
	}
	found := false
	for _, step := range envelope.Plan.Steps {
		if step.ID != a.StepID {
			continue
		}
		if found {
			return errors.New("duplicate original plan step")
		}
		found = true
		hash, err := data.ReconcileEffectStepHash(step)
		if err != nil || hash != a.OriginalStepHash {
			return errors.New("original step contract changed")
		}
		if a.Evidence.StepResult.Observation != nil && a.Evidence.StepResult.Observation.Surface != step.Target.Surface {
			return errors.New("reconciliation observation changed original surface")
		}
	}
	if !found {
		return errors.New("original step missing from immutable plan")
	}
	max := 0
	originalOutcome := false
	for _, e := range p.Events {
		if e == nil || e.Sequence == nil {
			return errors.New("complete original audit cursor required")
		}
		if *e.Sequence > max {
			max = *e.Sequence
		}
		if same(e.Id, a.AuditID) {
			return errors.New("reconciliation event already exists; read exact committed projection")
		}
		if same(e.AttemptId, a.AttemptID) && same(e.Kind, "outcome") && same(e.PayloadJson, a.OriginalEvidenceJSON) {
			originalOutcome = true
		}
	}
	if a.AuditSequence != max+1 || !originalOutcome {
		return errors.New("original outcome and next immutable audit sequence required")
	}
	var old *Effect
	for _, e := range p.Effects {
		if e != nil && same(e.Id, a.EffectID) {
			if old != nil {
				return errors.New("duplicate original effect")
			}
			old = e
		}
	}
	if old == nil || !same(old.AttemptId, a.AttemptID) || !same(old.RunId, a.RunID) || !same(old.BusinessKey, a.BusinessKey) || !same(old.EvidenceJson, a.OriginalEvidenceJSON) || !sameInt(old.Revision, a.EffectRevision) || old.State == nil || (*old.State != "intent" && *old.State != "unknown") {
		return errors.New("original unresolved effect correlation changed")
	}
	// Other unresolved effects remain untouched; a stopped run is not verified business success.
	return nil
}
func (h *RunLifecycle) AfterSequence(context.Context, *Run, xhandler.LifecycleContext[Run, xhandler.NoParent, ReconcileEffectOutput]) error {
	return nil
}
func (h *RunLifecycle) AfterQueue(context.Context, *Run, xhandler.LifecycleContext[Run, xhandler.NoParent, ReconcileEffectOutput]) error {
	return nil
}
func (h *RunLifecycle) Finalize(context.Context, *ReconcileEffectInput, *ReconcileEffectOutput, xhandler.Outcome) error {
	return nil
}

type EffectLifecycle struct{}

func EffectLifecycleDatlyType() reflect.Type { return reflect.TypeOf((*EffectLifecycle)(nil)).Elem() }

var EffectLifecycleHooks = new(EffectLifecycle)
var EffectLifecycleDatly = EffectLifecycleDatlyType()

func (h *EffectLifecycle) Init(ctx context.Context, e *Effect, s xhandler.LifecycleContext[Effect, Run, ReconcileEffectOutput]) error {
	if s.Previous != nil && s.Previous.Revision != nil {
		next := *s.Previous.Revision + 1
		e.SetRevision(&next)
	}
	return nil
}
func (h *EffectLifecycle) Validate(ctx context.Context, e *Effect, s xhandler.LifecycleContext[Effect, Run, ReconcileEffectOutput]) error {
	a, err := data.RequireReconcileEffectAuthority(ctx)
	if err != nil {
		return err
	}
	p := s.Previous
	if s.Parent == nil || !same(s.Parent.Id, a.RunID) || p == nil || !same(p.Namespace, a.Namespace) || !same(p.Id, a.EffectID) || !same(p.AttemptId, a.AttemptID) || !same(p.RunId, a.RunID) || !same(p.BusinessKey, a.BusinessKey) || !same(p.EvidenceJson, a.OriginalEvidenceJSON) || !sameInt(p.Revision, a.EffectRevision) || !sameInt(e.Revision, a.EffectRevision+1) || !same(e.State, "confirmed") || !same(e.EvidenceJson, a.EvidenceJSON) {
		return errors.New("exact unresolved effect CAS and verified proof required")
	}
	if p.State == nil || (*p.State != "intent" && *p.State != "unknown") {
		return errors.New("resolved effect cannot be reconciled again")
	}
	if e.BusinessKey != nil && !same(e.BusinessKey, a.BusinessKey) {
		return errors.New("business identity is immutable")
	}
	if len(e.Milestones) != 1 {
		return errors.New("one new verified milestone required")
	}
	if len(p.Milestones) > 0 {
		return errors.New("existing milestone history cannot be overwritten")
	}
	return nil
}
func (h *EffectLifecycle) AfterSequence(context.Context, *Effect, xhandler.LifecycleContext[Effect, Run, ReconcileEffectOutput]) error {
	return nil
}
func (h *EffectLifecycle) AfterQueue(context.Context, *Effect, xhandler.LifecycleContext[Effect, Run, ReconcileEffectOutput]) error {
	return nil
}

type MilestoneLifecycle struct{}

func MilestoneLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*MilestoneLifecycle)(nil)).Elem()
}

var MilestoneLifecycleHooks = new(MilestoneLifecycle)
var MilestoneLifecycleDatly = MilestoneLifecycleDatlyType()

func (h *MilestoneLifecycle) Init(context.Context, *Milestone, xhandler.LifecycleContext[Milestone, Effect, ReconcileEffectOutput]) error {
	return nil
}
func (h *MilestoneLifecycle) Validate(ctx context.Context, m *Milestone, s xhandler.LifecycleContext[Milestone, Effect, ReconcileEffectOutput]) error {
	a, err := data.RequireReconcileEffectAuthority(ctx)
	if err != nil {
		return err
	}
	if s.Previous != nil || s.Parent == nil || !same(s.Parent.Id, a.EffectID) {
		return fmt.Errorf("milestone must be newly appended to original effect")
	}
	return validateMilestone(m, a)
}
func (h *MilestoneLifecycle) AfterSequence(context.Context, *Milestone, xhandler.LifecycleContext[Milestone, Effect, ReconcileEffectOutput]) error {
	return nil
}
func (h *MilestoneLifecycle) AfterQueue(context.Context, *Milestone, xhandler.LifecycleContext[Milestone, Effect, ReconcileEffectOutput]) error {
	return nil
}

type EventLifecycle struct{}

func EventLifecycleDatlyType() reflect.Type { return reflect.TypeOf((*EventLifecycle)(nil)).Elem() }

var EventLifecycleHooks = new(EventLifecycle)
var EventLifecycleDatly = EventLifecycleDatlyType()

func (h *EventLifecycle) Init(context.Context, *Event, xhandler.LifecycleContext[Event, Run, ReconcileEffectOutput]) error {
	return nil
}
func (h *EventLifecycle) Validate(ctx context.Context, e *Event, s xhandler.LifecycleContext[Event, Run, ReconcileEffectOutput]) error {
	a, err := data.RequireReconcileEffectAuthority(ctx)
	if err != nil {
		return err
	}
	if s.Previous != nil || s.Parent == nil || !same(s.Parent.Id, a.RunID) {
		return errors.New("reconciliation audit must be newly appended")
	}
	return validateEvent(e, a)
}
func (h *EventLifecycle) AfterSequence(context.Context, *Event, xhandler.LifecycleContext[Event, Run, ReconcileEffectOutput]) error {
	return nil
}
func (h *EventLifecycle) AfterQueue(context.Context, *Event, xhandler.LifecycleContext[Event, Run, ReconcileEffectOutput]) error {
	return nil
}
