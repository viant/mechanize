package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/recoveryload"
	"github.com/viant/mechanize/data/repairadmit"
	"github.com/viant/mechanize/model"
	core "github.com/viant/mechanize/recovery"
)

type AdmissionRequest struct {
	ContextRequest
	Patch json.RawMessage `json:"patch"`
}
type AdmissionResult struct {
	Status          string           `json:"status"`
	Reason          string           `json:"reason,omitempty"`
	Reference       *RepairReference `json:"reference,omitempty"`
	CommitConfirmed bool             `json:"commitConfirmed"`
	ReadyToResume   bool             `json:"readyToResume"`
}

func (s *Service) Admit(ctx context.Context, requested auth.Principal, request AdmissionRequest) (result AdmissionResult, resultErr error) {
	result = AdmissionResult{Status: "needsAttention"}
	var release func() error
	defer func() {
		if release != nil {
			if err := release(); err != nil {
				resultErr = errors.Join(resultErr, err)
				result.Status = "needsAttention"
				result.Reason = "repair admission guard cleanup unconfirmed"
				result.ReadyToResume = false
			}
		}
	}()
	p, err := s.bound(ctx, requested)
	if err != nil {
		return result, err
	}
	patch, err := core.DecodePatch(request.Patch)
	if err != nil {
		return result, err
	}
	patchHash := core.Hash(patch)
	repairID := core.Hash([]string{p.Namespace, request.RunID, request.ExpectedPlanID, patchHash})
	snapshot, err := s.Snapshot(ctx, p, request.RunID)
	if err != nil {
		return result, err
	}
	// Exact reconciliation precedes expected-parent admission checks. An earlier
	// commit can have moved the run to the new immutable plan before reply loss.
	for _, old := range snapshot.Raw.Repairs {
		if old.Id != nil && *old.Id == repairID {
			ref, refErr := repairReference(old)
			if refErr != nil {
				return result, refErr
			}
			if ref.ParentPlanID != request.ExpectedPlanID || ref.ParentHash != patch.BaseHash || ref.ObjectiveHash != patch.ObjectiveHash || ref.PatchHash != patchHash || ref.Revision != request.ExpectedRevision+1 {
				return result, errors.New("immutable repair replay conflicts with original admission")
			}
			result.Reference = &ref
			result.CommitConfirmed = true
			if s.options.Guard == nil || s.options.RuntimeReady == nil {
				result.Reason = "stopped runtime repair/lineage admission binding unavailable"
				return result, nil
			}
			release, err = s.options.Guard(ctx, p, snapshot.Reference)
			if err != nil {
				return result, err
			}
			if release == nil {
				return result, errors.New("complete stopped runtime admission guard required")
			}
			current, err := s.Snapshot(ctx, p, request.RunID)
			if err != nil {
				return result, err
			}
			if current.Reference.PlanID != ref.NewPlanID || current.Reference.Revision != ref.Revision || current.Unknown || (current.Reference.Status != "paused" && current.Reference.Status != "new") || current.Repair == nil || *current.Repair != ref {
				result.Reason = "committed repair is not the current stopped resumable revision"
				return result, nil
			}
			if err = s.options.RuntimeReady(ctx, p); err != nil {
				result.Reason = "runtime repair lineage cannot safely resume"
				return result, nil
			}
			result.Status = "admitted"
			result.ReadyToResume = true
			return result, nil
		}
	}
	if err = expected(snapshot, request.ContextRequest); err != nil {
		result.Reason = err.Error()
		return result, nil
	}
	if s.options.Guard == nil || s.options.RuntimeReady == nil {
		result.Reason = "stopped runtime repair/lineage admission binding unavailable"
		return result, nil
	}
	release, err = s.options.Guard(ctx, p, snapshot.Reference)
	if err != nil {
		return result, err
	}
	if release == nil {
		return result, errors.New("complete stopped runtime admission guard required")
	}
	snapshot, err = s.Snapshot(ctx, p, request.RunID)
	if err != nil {
		return result, err
	}
	if err = expected(snapshot, request.ContextRequest); err != nil {
		return result, err
	}
	if err = s.options.RuntimeReady(ctx, p); err != nil {
		result.Reason = "runtime repair lineage cannot safely resume"
		return result, nil
	}
	private, evidence, err := s.prepare(ctx, p, snapshot)
	if err != nil {
		result.Reason = err.Error()
		return result, nil
	}
	if _, err = redact(private, snapshot); err != nil {
		result.Reason = err.Error()
		return result, nil
	}
	revision, err := core.Validate(ctx, private, patch)
	if err != nil {
		return result, err
	}
	if err = preserveEffectArguments(snapshot, revision.Plan); err != nil {
		return result, err
	}
	for _, surface := range surfaces(revision.Plan) {
		if err = s.options.Authorize(ctx, p, surface); err != nil {
			return result, err
		}
	}
	if err = s.options.VerifyEvidence(ctx, p, snapshot, evidence); err != nil {
		return result, err
	}
	if time.Now().After(evidence.ValidUntil) {
		return result, errors.New("recovery evidence expired before admission")
	}
	reservation := routeCost(patch.RemainingSteps)
	ref := RepairReference{ID: repairID, RunID: request.RunID, NewPlanID: core.Hash([]string{"repair-plan", repairID, revision.Hash}), ParentPlanID: snapshot.Reference.PlanID, ParentContentHash: snapshot.Reference.ContentHash, ParentHash: revision.ParentHash, PlanHash: revision.Hash, ObjectiveHash: revision.ObjectiveHash, PatchHash: patchHash, Revision: snapshot.Reference.Revision + 1, CompletedSteps: revision.ResumeStep, IncidentID: snapshot.IncidentID}
	graph, err := admissionGraph(p.Namespace, snapshot, revision.Plan, ref, evidence, private.IncidentBudget, reservation)
	if err != nil {
		return result, err
	}
	expectedGraph, err := cloneGraph(graph.Records)
	if err != nil {
		return result, err
	}
	expectedGraph.SetRevision(ptr(ref.Revision))
	expectedGraph.Workflow.SetRevision(ptr(value(graph.Records.Workflow.Revision) + 1))
	expectedGraph.Incidents[0].SetRevision(ptr(value(graph.Records.Incidents[0].Revision) + 1))
	ctx, err = data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	if err != nil {
		return result, err
	}
	ctx, err = repairadmit.WithPermit(ctx, repairadmit.Permit{Namespace: p.Namespace, RunID: ref.RunID, ParentPlanID: ref.ParentPlanID, ExpectedRevision: snapshot.Reference.Revision, ValidUntil: evidence.ValidUntil, Expected: expectedGraph, ExpectedPlan: graph.Plans[0], AnchorID: *graph.Id})
	if err != nil {
		return result, err
	}
	input := &repairadmit.AdmitRepairInput{}
	input.SetNamespace(p.Namespace)
	input.SetRunID(ref.RunID)
	input.SetParentPlanID(ref.ParentPlanID)
	input.SetAnchorID(*graph.Id)
	input.SetAdmitRepair([]*repairadmit.RepairScope{graph})
	result.Reference = &ref
	if _, err = s.invoke(ctx, p, "repairadmit", "AdmitRepair", "PATCH", input, true); err != nil {
		// Retain the exact reference. A subsequent generated read can establish
		// admission, but this uncertain response never enables resume by itself.
		result.Reason = "repair commit failed or acknowledgement is unknown; reconcile exact immutable reference before resume"
		return result, err
	}
	result.CommitConfirmed = true
	after, err := s.Snapshot(ctx, p, request.RunID)
	if err != nil {
		result.Reason = "committed repair requires generated lineage reconciliation"
		return result, err
	}
	if after.Reference.PlanID != ref.NewPlanID || after.Reference.Revision != ref.Revision || after.Repair == nil || *after.Repair != ref {
		return result, errors.New("committed repair lineage proof differs")
	}
	result.Status = "admitted"
	result.CommitConfirmed = true
	result.ReadyToResume = true
	return result, nil
}
func preserveEffectArguments(snapshot Snapshot, next model.Plan) error {
	original := map[string]model.Step{}
	for _, step := range snapshot.Plan.Steps[snapshot.CompletedSteps:] {
		if step.Effect.Class != model.ReadOnly {
			key, err := canonicalKey(step.Effect.BusinessKey, snapshot.Values)
			if err != nil {
				return err
			}
			original[key] = step
		}
	}
	for _, step := range next.Steps[snapshot.CompletedSteps:] {
		if step.Effect.Class != model.ReadOnly {
			key, err := canonicalKey(step.Effect.BusinessKey, snapshot.Values)
			if err != nil {
				return err
			}
			old, ok := original[key]
			if !ok || !reflect.DeepEqual(step.Arguments, old.Arguments) {
				return errors.New("repair cannot change remaining business effect input arguments")
			}
		}
	}
	return nil
}
func routeCost(steps []model.Step) int {
	total := int64(0)
	for _, step := range steps {
		total += step.TimeoutMs
		for _, predicate := range []*model.Predicate{step.Precondition, step.Postcondition, step.Effect.Reconcile} {
			if predicate != nil {
				total += predicate.TimeoutMs
			}
		}
	}
	if total < 1 {
		return 1
	}
	return int(total)
}
func admissionGraph(namespace string, snapshot Snapshot, plan model.Plan, ref RepairReference, evidence Evidence, incidentPolicy core.Budget, reservation int) (*repairadmit.RepairScope, error) {
	envelope := planEnvelope{Plan: plan, Inputs: snapshot.Inputs}
	content, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	root := &repairadmit.RepairRun{}
	root.SetNamespace(ptr(namespace))
	root.SetId(ptr(ref.RunID))
	root.SetPlanId(ptr(ref.NewPlanID))
	root.SetRevision(ptr(snapshot.Reference.Revision))
	root.SetStatus(snapshot.Raw.Status)
	root.SetCreatedAt(snapshot.Raw.CreatedAt)
	root.SetUpdatedAt(ptr(now))
	if snapshot.Raw.EndlySessionId != nil {
		root.SetEndlySessionId(snapshot.Raw.EndlySessionId)
	}
	if snapshot.Raw.EndlyOperationId != nil {
		root.SetEndlyOperationId(snapshot.Raw.EndlyOperationId)
	}
	producer := &repairadmit.PlanRevision{}
	producer.SetNamespace(ptr(namespace))
	producer.SetId(ptr(ref.NewPlanID))
	producer.SetParentId(ptr(ref.ParentPlanID))
	producer.SetObjectiveId(ptr(snapshot.Reference.ObjectiveID))
	producer.SetContentHash(ptr(digest(content)))
	producer.SetContentJson(ptr(string(content)))
	producer.SetCreatedAt(ptr(now))

	policy := snapshot.Plan.Recovery
	workflow := &repairadmit.WorkflowBudget{}
	workflow.SetNamespace(ptr(namespace))
	workflow.SetRunId(ptr(ref.RunID))
	workflow.SetMaxRepairs(ptr(policy.MaxRepairs))
	workflow.SetMaxElapsedMs(ptr(int(policy.MaxElapsedMs)))
	oldWorkflowRev, used, elapsed := 0, 0, 0
	if old := snapshot.Raw.Workflow; old != nil {
		oldWorkflowRev = value(old.Revision)
		used = value(old.UsedRepairs)
		elapsed = value(old.ElapsedMs)
	}
	workflow.SetRevision(ptr(oldWorkflowRev))
	workflow.SetUsedRepairs(ptr(used + 1))
	workflow.SetElapsedMs(ptr(elapsed + reservation))
	root.SetWorkflow(workflow)
	// Context validation already binds these limits to immutable workflow policy
	// and trusted incident configuration; reservation cannot exceed either bound.
	incident := &repairadmit.IncidentBudget{}
	incident.SetNamespace(ptr(namespace))
	incident.SetRunId(ptr(ref.RunID))
	incident.SetId(ptr(ref.IncidentID))
	incident.SetMaxRepairs(ptr(incidentPolicy.MaxRepairs))
	incident.SetMaxElapsedMs(ptr(int(incidentPolicy.MaxElapsedMs)))
	oldIncidentRev, oldUsed, oldElapsed := 0, 0, 0
	for _, old := range snapshot.Raw.Incidents {
		if old.Id != nil && *old.Id == ref.IncidentID {
			oldIncidentRev = value(old.Revision)
			oldUsed = value(old.UsedRepairs)
			oldElapsed = value(old.ElapsedMs)
			incident.SetMaxRepairs(old.MaxRepairs)
			incident.SetMaxElapsedMs(old.MaxElapsedMs)
		}
	}
	incident.SetRevision(ptr(oldIncidentRev))
	incident.SetUsedRepairs(ptr(oldUsed + 1))
	incident.SetElapsedMs(ptr(oldElapsed + reservation))
	root.SetIncidents([]*repairadmit.IncidentBudget{incident})
	repair := &repairadmit.RepairRevision{}
	repair.SetNamespace(ptr(namespace))
	repair.SetId(ptr(ref.ID))
	repair.SetRunId(ptr(ref.RunID))
	repair.SetParentPlanId(ptr(ref.ParentPlanID))
	repair.SetNewPlanId(ptr(ref.NewPlanID))
	repair.SetParentContentHash(ptr(ref.ParentContentHash))
	repair.SetParentPlanHash(ptr(ref.ParentHash))
	repair.SetPlanHash(ptr(ref.PlanHash))
	repair.SetObjectiveHash(ptr(ref.ObjectiveHash))
	repair.SetPatchHash(ptr(ref.PatchHash))
	refs, _ := json.Marshal(evidence.EvidenceRefs)
	repair.SetEvidenceJson(ptr(string(refs)))
	repair.SetPolicyHash(ptr(evidence.PolicyHash))
	repair.SetCompletedSteps(ptr(ref.CompletedSteps))
	repair.SetIncidentId(ptr(ref.IncidentID))
	repair.SetRunRevision(ptr(ref.Revision))
	repair.SetAdmittedAt(ptr(now))
	lineages, err := buildLineage(namespace, snapshot, plan, ref)
	if err != nil {
		return nil, err
	}
	repair.SetLineage(lineages)
	root.SetRepairs([]*repairadmit.RepairRevision{repair})
	sequence := 1
	for _, event := range snapshot.Raw.Events {
		if event.Sequence != nil && *event.Sequence >= sequence {
			sequence = *event.Sequence + 1
		}
	}
	audit := &repairadmit.Event{}
	audit.SetNamespace(ptr(namespace))
	audit.SetId(ptr(core.Hash([]string{"repair-admitted", ref.ID})))
	audit.SetRunId(ptr(ref.RunID))
	audit.SetSequence(ptr(sequence))
	audit.SetKind(ptr("repairAdmitted"))
	payload, _ := json.Marshal(ref)
	audit.SetPayloadJson(ptr(string(payload)))
	audit.SetCreatedAt(ptr(now))
	root.SetEvents([]*repairadmit.Event{audit})
	var anchor *recoveryload.Milestone
	for _, milestone := range snapshot.Raw.Milestones {
		if milestone.State != nil && *milestone.State == "verified" && milestone.Id != nil {
			anchor = milestone
			break
		}
	}
	if anchor == nil {
		return nil, errors.New("confirmed milestone anchor required; empty/readonly repair admission is not qualified")
	}
	scope := &repairadmit.RepairScope{}
	scope.SetNamespace(ptr(namespace))
	scope.SetId(anchor.Id)
	scope.SetRunId(anchor.RunId)
	scope.SetAttemptId(anchor.AttemptId)
	scope.SetState(anchor.State)
	if anchor.EvidenceJson != nil {
		scope.SetEvidenceJson(anchor.EvidenceJson)
	}
	scope.SetRecords(root)
	scope.SetPlans([]*repairadmit.PlanRevision{producer})
	return scope, nil
}

func buildLineage(namespace string, snapshot Snapshot, next model.Plan, ref RepairReference) ([]*repairadmit.RepairLineage, error) {
	activeByAttempt := map[string]Lineage{}
	for _, entry := range snapshot.Lineage {
		activeByAttempt[entry.AttemptID] = entry
	}
	attempts := map[string]int{}
	for i, attempt := range snapshot.Raw.Attempts {
		if attempt.Id != nil {
			attempts[*attempt.Id] = i
		}
	}
	byID := map[string]int{}
	byKey := map[string]int{}
	for i, step := range next.Steps {
		byID[step.ID] = i
		if step.Effect.Class != model.ReadOnly {
			key, err := canonicalKey(step.Effect.BusinessKey, snapshot.Values)
			if err != nil {
				return nil, err
			}
			byKey[key] = i
		}
	}
	out := []*repairadmit.RepairLineage{}
	for _, effect := range snapshot.Raw.Effects {
		if effect.State == nil || (*effect.State != "confirmed" && *effect.State != "absent") || effect.AttemptId == nil || effect.Id == nil || effect.BusinessKey == nil || effect.EvidenceJson == nil {
			return nil, errors.New("unknown effect cannot enter repair lineage")
		}
		position, ok := attempts[*effect.AttemptId]
		if !ok {
			return nil, errors.New("original attempt absent")
		}
		attempt := snapshot.Raw.Attempts[position]
		stepID := *attempt.StepId
		if inherited, ok := activeByAttempt[*attempt.Id]; ok {
			stepID = inherited.StepID
		}
		index, exists := byID[stepID]
		if *effect.State == "absent" {
			index, exists = byKey[*effect.BusinessKey]
		}
		if !exists {
			return nil, errors.New("repair cannot drop original confirmed/absent effect identity")
		}
		row := &repairadmit.RepairLineage{}
		row.SetNamespace(ptr(namespace))
		row.SetId(ptr(core.Hash([]string{ref.ID, *attempt.Id})))
		row.SetRunId(ptr(ref.RunID))
		row.SetRepairId(ptr(ref.ID))
		row.SetNewPlanId(ptr(ref.NewPlanID))
		row.SetStepId(ptr(next.Steps[index].ID))
		row.SetStepIndex(ptr(index))
		row.SetOriginalPlanId(attempt.PlanId)
		row.SetOriginalStepId(attempt.StepId)
		row.SetAttemptId(attempt.Id)
		row.SetEffectId(effect.Id)
		row.SetBusinessKey(effect.BusinessKey)
		row.SetResultHash(ptr(digest([]byte(*effect.EvidenceJson))))
		row.SetState(effect.State)
		out = append(out, row)
	}
	return out, nil
}
func cloneGraph(root *repairadmit.RepairRun) (*repairadmit.RepairRun, error) {
	body, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	var copy repairadmit.RepairRun
	err = json.Unmarshal(body, &copy)
	return &copy, err
}
func ptr[T any](v T) *T { return &v }
func value(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
