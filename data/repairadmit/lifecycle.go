package repairadmit

import (
	context "context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/model"
	core "github.com/viant/mechanize/recovery"
	xhandler "github.com/viant/xdatly/handler"
	reflect "reflect"
)

// RepairRunLifecycle customizes role Input.AdmitRepair.
type RepairRunLifecycle struct{}

func RepairRunLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*RepairRunLifecycle)(nil)).Elem()
}

var (
	RepairRunLifecycleHooks = new(RepairRunLifecycle)
	RepairRunLifecycleDatly = RepairRunLifecycleDatlyType()
)

func (hooks *RepairRunLifecycle) Init(ctx context.Context, entity *RepairRun, state xhandler.LifecycleContext[RepairRun, RepairScope, AdmitRepairOutput]) error {
	if state.Previous != nil && state.Previous.Revision != nil {
		entity.SetRevision(increment(state.Previous.Revision, entity.Revision))
	}
	return nil
}
func (hooks *RepairRunLifecycle) Validate(ctx context.Context, entity *RepairRun, state xhandler.LifecycleContext[RepairRun, RepairScope, AdmitRepairOutput]) error {
	permit, err := requirePermit(ctx)
	if err != nil {
		return err
	}
	previous := state.Previous
	if previous == nil || previous.Id == nil || previous.Namespace == nil || previous.PlanId == nil || previous.Revision == nil || previous.Status == nil || *previous.Id != permit.RunID || *previous.Namespace != permit.Namespace || *previous.PlanId != permit.ParentPlanID || *previous.Revision != permit.ExpectedRevision || (*previous.Status != "paused" && *previous.Status != "new") {
		return errors.New("exact stopped owned run CAS boundary required")
	}
	for _, effect := range previous.Unresolved {
		if effect.State == nil || *effect.State == "intent" || *effect.State == "unknown" {
			return errors.New("unresolved effect blocks repair admission")
		}
	}
	want := permit.Expected
	if !sameOptional(entity.Namespace, want.Namespace) || !sameOptional(entity.Id, want.Id) || !sameOptional(entity.PlanId, want.PlanId) || !sameOptional(entity.Revision, want.Revision) || !sameOptional(entity.UpdatedAt, want.UpdatedAt) {
		return errors.New("repair run target differs from validated permit")
	}
	if !sameOptional(entity.Status, previous.Status) || !sameOptional(entity.CreatedAt, previous.CreatedAt) || !sameOptional(entity.EndlySessionId, previous.EndlySessionId) || !sameOptional(entity.EndlyOperationId, previous.EndlyOperationId) {
		return errors.New("repair cannot alter run lifecycle/session identity")
	}
	if entity.Workflow == nil || len(entity.Incidents) != 1 || len(entity.Repairs) != 1 || len(entity.Events) != 1 {
		return errors.New("one atomic repair revision, incident/workflow reservation and audit required")
	}
	return nil
}
func (hooks *RepairRunLifecycle) AfterSequence(ctx context.Context, entity *RepairRun, state xhandler.LifecycleContext[RepairRun, RepairScope, AdmitRepairOutput]) error {
	return nil
}
func (hooks *RepairRunLifecycle) AfterQueue(ctx context.Context, entity *RepairRun, state xhandler.LifecycleContext[RepairRun, RepairScope, AdmitRepairOutput]) error {
	return nil
}
func (hooks *RepairRunLifecycle) Finalize(ctx context.Context, input *AdmitRepairInput, output *AdmitRepairOutput, outcome xhandler.Outcome) error {
	return nil
}

// PlanRevisionLifecycle customizes role Input.AdmitRepair.Plans.
type PlanRevisionLifecycle struct{}

func PlanRevisionLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*PlanRevisionLifecycle)(nil)).Elem()
}

var (
	PlanRevisionLifecycleHooks = new(PlanRevisionLifecycle)
	PlanRevisionLifecycleDatly = PlanRevisionLifecycleDatlyType()
)

func (hooks *PlanRevisionLifecycle) Init(ctx context.Context, entity *PlanRevision, state xhandler.LifecycleContext[PlanRevision, RepairScope, AdmitRepairOutput]) error {
	return nil
}
func (hooks *PlanRevisionLifecycle) Validate(ctx context.Context, entity *PlanRevision, state xhandler.LifecycleContext[PlanRevision, RepairScope, AdmitRepairOutput]) error {
	permit, err := requirePermit(ctx)
	if err != nil {
		return err
	}
	if state.Previous != nil || permit.ExpectedPlan == nil || !sameLeaf(entity, permit.ExpectedPlan) {
		return errors.New("immutable validated repair plan required")
	}
	if entity.ContentJson == nil || entity.ContentHash == nil || core.Hash(json.RawMessage(*entity.ContentJson)) != *entity.ContentHash {
		return errors.New("repair envelope hash mismatch")
	}
	var envelope struct {
		Plan   model.Plan             `json:"plan"`
		Inputs map[string]model.Value `json:"inputs"`
	}
	if err = json.Unmarshal([]byte(*entity.ContentJson), &envelope); err != nil {
		return err
	}
	return envelope.Plan.Validate()
}
func (hooks *PlanRevisionLifecycle) AfterSequence(ctx context.Context, entity *PlanRevision, state xhandler.LifecycleContext[PlanRevision, RepairScope, AdmitRepairOutput]) error {
	return nil
}
func (hooks *PlanRevisionLifecycle) AfterQueue(ctx context.Context, entity *PlanRevision, state xhandler.LifecycleContext[PlanRevision, RepairScope, AdmitRepairOutput]) error {
	return nil
}

// WorkflowBudgetLifecycle customizes role Input.AdmitRepair.Workflow.
type WorkflowBudgetLifecycle struct{}

func WorkflowBudgetLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*WorkflowBudgetLifecycle)(nil)).Elem()
}

var (
	WorkflowBudgetLifecycleHooks = new(WorkflowBudgetLifecycle)
	WorkflowBudgetLifecycleDatly = WorkflowBudgetLifecycleDatlyType()
)

func (hooks *WorkflowBudgetLifecycle) Init(ctx context.Context, entity *WorkflowBudget, state xhandler.LifecycleContext[WorkflowBudget, RepairRun, AdmitRepairOutput]) error {
	entity.SetRevision(increment(func() *int {
		if state.Previous != nil {
			return state.Previous.Revision
		}
		return nil
	}(), entity.Revision))
	return nil
}
func (hooks *WorkflowBudgetLifecycle) Validate(ctx context.Context, entity *WorkflowBudget, state xhandler.LifecycleContext[WorkflowBudget, RepairRun, AdmitRepairOutput]) error {
	permit, err := requirePermit(ctx)
	if err != nil {
		return err
	}
	if !sameLeaf(entity, permit.Expected.Workflow) {
		return errors.New("validated workflow budget reservation required")
	}
	return validateBudget(entity.MaxRepairs, entity.UsedRepairs, entity.MaxElapsedMs, entity.ElapsedMs, func() *WorkflowBudget { return state.Previous }())
}
func (hooks *WorkflowBudgetLifecycle) AfterSequence(ctx context.Context, entity *WorkflowBudget, state xhandler.LifecycleContext[WorkflowBudget, RepairRun, AdmitRepairOutput]) error {
	return nil
}
func (hooks *WorkflowBudgetLifecycle) AfterQueue(ctx context.Context, entity *WorkflowBudget, state xhandler.LifecycleContext[WorkflowBudget, RepairRun, AdmitRepairOutput]) error {
	return nil
}

// IncidentBudgetLifecycle customizes role Input.AdmitRepair.Incidents.
type IncidentBudgetLifecycle struct{}

func IncidentBudgetLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*IncidentBudgetLifecycle)(nil)).Elem()
}

var (
	IncidentBudgetLifecycleHooks = new(IncidentBudgetLifecycle)
	IncidentBudgetLifecycleDatly = IncidentBudgetLifecycleDatlyType()
)

func (hooks *IncidentBudgetLifecycle) Init(ctx context.Context, entity *IncidentBudget, state xhandler.LifecycleContext[IncidentBudget, RepairRun, AdmitRepairOutput]) error {
	entity.SetRevision(increment(func() *int {
		if state.Previous != nil {
			return state.Previous.Revision
		}
		return nil
	}(), entity.Revision))
	return nil
}
func (hooks *IncidentBudgetLifecycle) Validate(ctx context.Context, entity *IncidentBudget, state xhandler.LifecycleContext[IncidentBudget, RepairRun, AdmitRepairOutput]) error {
	permit, err := requirePermit(ctx)
	if err != nil {
		return err
	}
	if len(permit.Expected.Incidents) != 1 || !sameLeaf(entity, permit.Expected.Incidents[0]) {
		return errors.New("validated incident budget reservation required")
	}
	var previous *WorkflowBudget
	if state.Previous != nil {
		p := state.Previous
		previous = &WorkflowBudget{MaxRepairs: p.MaxRepairs, UsedRepairs: p.UsedRepairs, MaxElapsedMs: p.MaxElapsedMs, ElapsedMs: p.ElapsedMs}
	}
	return validateBudget(entity.MaxRepairs, entity.UsedRepairs, entity.MaxElapsedMs, entity.ElapsedMs, previous)
}
func (hooks *IncidentBudgetLifecycle) AfterSequence(ctx context.Context, entity *IncidentBudget, state xhandler.LifecycleContext[IncidentBudget, RepairRun, AdmitRepairOutput]) error {
	return nil
}
func (hooks *IncidentBudgetLifecycle) AfterQueue(ctx context.Context, entity *IncidentBudget, state xhandler.LifecycleContext[IncidentBudget, RepairRun, AdmitRepairOutput]) error {
	return nil
}

// RepairRevisionLifecycle customizes role Input.AdmitRepair.Repairs.
type RepairRevisionLifecycle struct{}

func RepairRevisionLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*RepairRevisionLifecycle)(nil)).Elem()
}

var (
	RepairRevisionLifecycleHooks = new(RepairRevisionLifecycle)
	RepairRevisionLifecycleDatly = RepairRevisionLifecycleDatlyType()
)

func (hooks *RepairRevisionLifecycle) Init(ctx context.Context, entity *RepairRevision, state xhandler.LifecycleContext[RepairRevision, RepairRun, AdmitRepairOutput]) error {
	return nil
}
func (hooks *RepairRevisionLifecycle) Validate(ctx context.Context, entity *RepairRevision, state xhandler.LifecycleContext[RepairRevision, RepairRun, AdmitRepairOutput]) error {
	permit, err := requirePermit(ctx)
	if err != nil {
		return err
	}
	if state.Previous != nil || len(permit.Expected.Repairs) != 1 {
		return errors.New("immutable repair provenance required")
	}
	want := *permit.Expected.Repairs[0]
	actual := *entity
	actual.Lineage = nil
	want.Lineage = nil
	if !sameLeaf(&actual, &want) || len(entity.Lineage) != len(permit.Expected.Repairs[0].Lineage) {
		return errors.New("repair provenance differs from validated admission")
	}
	return nil
}
func (hooks *RepairRevisionLifecycle) AfterSequence(ctx context.Context, entity *RepairRevision, state xhandler.LifecycleContext[RepairRevision, RepairRun, AdmitRepairOutput]) error {
	return nil
}
func (hooks *RepairRevisionLifecycle) AfterQueue(ctx context.Context, entity *RepairRevision, state xhandler.LifecycleContext[RepairRevision, RepairRun, AdmitRepairOutput]) error {
	return nil
}

// RepairLineageLifecycle customizes role Input.AdmitRepair.Repairs.Lineage.
type RepairLineageLifecycle struct{}

func RepairLineageLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*RepairLineageLifecycle)(nil)).Elem()
}

var (
	RepairLineageLifecycleHooks = new(RepairLineageLifecycle)
	RepairLineageLifecycleDatly = RepairLineageLifecycleDatlyType()
)

func (hooks *RepairLineageLifecycle) Init(ctx context.Context, entity *RepairLineage, state xhandler.LifecycleContext[RepairLineage, RepairRevision, AdmitRepairOutput]) error {
	return nil
}
func (hooks *RepairLineageLifecycle) Validate(ctx context.Context, entity *RepairLineage, state xhandler.LifecycleContext[RepairLineage, RepairRevision, AdmitRepairOutput]) error {
	permit, err := requirePermit(ctx)
	if err != nil {
		return err
	}
	if state.Previous != nil {
		return errors.New("completed/absent lineage is immutable")
	}
	for _, want := range permit.Expected.Repairs[0].Lineage {
		if sameLeaf(entity, want) {
			return nil
		}
	}
	return errors.New("repair lineage differs from original exact-key history")
}
func (hooks *RepairLineageLifecycle) AfterSequence(ctx context.Context, entity *RepairLineage, state xhandler.LifecycleContext[RepairLineage, RepairRevision, AdmitRepairOutput]) error {
	return nil
}
func (hooks *RepairLineageLifecycle) AfterQueue(ctx context.Context, entity *RepairLineage, state xhandler.LifecycleContext[RepairLineage, RepairRevision, AdmitRepairOutput]) error {
	return nil
}

// EventLifecycle customizes role Input.AdmitRepair.Events.
type EventLifecycle struct{}

func EventLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*EventLifecycle)(nil)).Elem()
}

var (
	EventLifecycleHooks = new(EventLifecycle)
	EventLifecycleDatly = EventLifecycleDatlyType()
)

func (hooks *EventLifecycle) Init(ctx context.Context, entity *Event, state xhandler.LifecycleContext[Event, RepairRun, AdmitRepairOutput]) error {
	return nil
}
func (hooks *EventLifecycle) Validate(ctx context.Context, entity *Event, state xhandler.LifecycleContext[Event, RepairRun, AdmitRepairOutput]) error {
	permit, err := requirePermit(ctx)
	if err != nil {
		return err
	}
	if state.Previous != nil || len(permit.Expected.Events) != 1 || !sameLeaf(entity, permit.Expected.Events[0]) {
		return errors.New("immutable repair audit required")
	}
	return nil
}
func (hooks *EventLifecycle) AfterSequence(ctx context.Context, entity *Event, state xhandler.LifecycleContext[Event, RepairRun, AdmitRepairOutput]) error {
	return nil
}
func (hooks *EventLifecycle) AfterQueue(ctx context.Context, entity *Event, state xhandler.LifecycleContext[Event, RepairRun, AdmitRepairOutput]) error {
	return nil
}

func validateBudget(max, used, maxMs, elapsed *int, previous *WorkflowBudget) error {
	if max == nil || used == nil || maxMs == nil || elapsed == nil || *max < 1 || *max > 10 || *maxMs < 1 || *maxMs > 3600000 || *used < 1 || *used > *max || *elapsed < 1 || *elapsed > *maxMs {
		return errors.New("finite repair budget required")
	}
	oldUsed, oldMs := 0, 0
	if previous != nil {
		if previous.MaxRepairs == nil || previous.MaxElapsedMs == nil || previous.UsedRepairs == nil || previous.ElapsedMs == nil || *previous.MaxRepairs != *max || *previous.MaxElapsedMs != *maxMs {
			return errors.New("repair budget policy is immutable")
		}
		oldUsed = *previous.UsedRepairs
		oldMs = *previous.ElapsedMs
	}
	if *used != oldUsed+1 || *elapsed <= oldMs {
		return errors.New("exact monotonic repair reservation required")
	}
	return nil
}
