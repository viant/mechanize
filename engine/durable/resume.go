package durable

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/viant/datly/standalone"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data/loadplan"
	"github.com/viant/mechanize/data/loadrun"
	repairs "github.com/viant/mechanize/engine/recovery"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"strings"
)

// LoadResume uses generated scoped readers to restore serializable state.
// Running after process death is resumable; terminal state and uncertainty are not.
func (b *Builder) LoadResume(ctx context.Context, p auth.Principal, runID string, expectedRevision int, expectedPlanID, expectedObjectiveID string) (integration.ResumeSnapshot, error) {
	var result integration.ResumeSnapshot
	if runID == "" || expectedRevision <= 0 || expectedPlanID == "" || expectedObjectiveID == "" {
		return result, errors.New("run, expected revision, plan and objective identity required")
	}
	epoch, err := b.options.LeaseEpoch(ctx, p)
	if err != nil {
		return result, err
	}
	if epoch <= 0 {
		return result, errors.New("held desktop fence required for resume")
	}
	ctx, user, err := b.bound(ctx, p, epoch)
	if err != nil {
		return result, err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	run, err := load(ctx, user.server, p, runID)
	if err != nil {
		return result, err
	}
	state, err := stateRead(ctx, user.server, p, runID)
	if err != nil {
		return result, err
	}
	if state.Revision != expectedRevision || state.PlanID != expectedPlanID {
		return result, errors.New("resume revision or immutable plan mismatch")
	}
	switch state.Status {
	case "running", "paused", "new":
	default:
		return result, errors.New("durable terminal run cannot be resumed")
	}
	if len(state.UnresolvedEffects) > 0 {
		return result, ErrNeedsReconciliation
	}
	input := &loadplan.LoadPlanInput{}
	input.SetNamespace(p.Namespace)
	input.SetPlanID(state.PlanID)
	raw, err := invoke(ctx, user.server, "loadplan", "LoadPlan", "GET", input, false)
	if err != nil {
		return result, err
	}
	output, ok := raw.(*loadplan.LoadPlanOutput)
	if !ok || len(output.Data) != 1 {
		return result, errors.New("authorized immutable plan not found")
	}
	plan := output.Data[0]
	if plan.ObjectiveId == nil || *plan.ObjectiveId != expectedObjectiveID || plan.ContentJson == nil || plan.ContentHash == nil {
		return result, errors.New("resume objective or plan content mismatch")
	}
	sum := sha256.Sum256([]byte(*plan.ContentJson))
	if hex.EncodeToString(sum[:]) != *plan.ContentHash {
		return result, errors.New("immutable plan content hash mismatch")
	}
	var envelope struct {
		Plan   model.Plan             `json:"plan"`
		Inputs map[string]model.Value `json:"inputs"`
	}
	if err = json.Unmarshal([]byte(*plan.ContentJson), &envelope); err != nil {
		return result, err
	}
	if err = envelope.Plan.Validate(); err != nil {
		return result, err
	}
	for _, value := range envelope.Inputs {
		if err = value.Validate(); err != nil {
			return result, err
		}
	}
	result = integration.ResumeSnapshot{RunID: runID, PlanID: state.PlanID, ObjectiveID: *plan.ObjectiveId, Status: state.Status, Revision: state.Revision, Plan: envelope.Plan, Inputs: envelope.Inputs, Values: state.Variables, Completed: map[string]integration.StepResult{}}
	if hasAncestorAttempts(run, state.PlanID) {
		snapshot, err := repairSnapshotLocked(ctx, user.server, p, runID, state.PlanID, envelope.Plan, envelope.Inputs)
		if err != nil {
			return result, err
		}
		if snapshot.Reference.Revision != expectedRevision || snapshot.Reference.ObjectiveID != expectedObjectiveID || snapshot.Reference.ContentHash != *plan.ContentHash {
			return result, errors.New("repair resume reference changed")
		}
		result.Completed = snapshot.Completed
		result.Values = map[string]model.Value{}
		for name, value := range snapshot.Values {
			if strings.HasPrefix(name, "binding.") {
				result.Values[strings.TrimPrefix(name, "binding.")] = value
			}
		}
		for stepID, evidence := range result.Completed {
			for _, step := range envelope.Plan.Steps {
				if step.ID == stepID && step.Bind != "" && evidence.Value != nil {
					result.Values[step.Bind] = *evidence.Value
				}
			}
		}
		return result, nil
	}
	attempts := map[string]string{}
	steps := map[string]model.Step{}
	for _, step := range envelope.Plan.Steps {
		steps[step.ID] = step
	}
	for _, attempt := range run.Attempts {
		if attempt.Id == nil || attempt.StepId == nil || attempt.PlanId == nil || *attempt.PlanId != state.PlanID {
			return result, errors.New("persisted attempt plan identity mismatch")
		}
		if _, ok = steps[*attempt.StepId]; !ok {
			return result, errors.New("persisted attempt step absent from immutable plan")
		}
		attempts[*attempt.Id] = *attempt.StepId
	}
	verifiedAttempts := map[string]bool{}
	for _, milestone := range state.Progress {
		if milestone.AttemptId == nil || milestone.State == nil || *milestone.State != "verified" {
			return result, errors.New("invalid persisted milestone")
		}
		if _, exists := attempts[*milestone.AttemptId]; !exists {
			return result, errors.New("milestone attempt absent from immutable plan")
		}
		verifiedAttempts[*milestone.AttemptId] = true
	}
	for _, effect := range run.Effects {
		if effect.State == nil || effect.AttemptId == nil || (*effect.State != "confirmed" && *effect.State != "absent") {
			return result, ErrNeedsReconciliation
		}
		stepID, exists := attempts[*effect.AttemptId]
		if !exists || effect.EvidenceJson == nil {
			return result, ErrNeedsReconciliation
		}
		var evidence integration.StepResult
		if err = json.Unmarshal([]byte(*effect.EvidenceJson), &evidence); err != nil {
			return result, ErrNeedsReconciliation
		}
		if *effect.State == "absent" {
			if evidence.DispatchState != "notDispatched" || verifiedAttempts[*effect.AttemptId] {
				return result, ErrNeedsReconciliation
			}
			// Proven absence is still a remaining step. It supplies no completed
			// milestone or output and cannot authorize overwriting its old intent.
			continue
		}
		if evidence.VerificationState != "verified" {
			return result, ErrNeedsReconciliation
		}
		step := steps[stepID]
		if step.Bind != "" && evidence.Value == nil {
			return result, errors.New("completed step binding lacks durable typed evidence")
		}
		if evidence.Value != nil {
			if err = evidence.Value.Validate(); err != nil {
				return result, err
			}
		}
		if _, exists := result.Completed[stepID]; exists {
			return result, ErrNeedsReconciliation
		}
		result.Completed[stepID] = evidence
	}
	if err = validateResumeBusinessKeys(envelope.Plan, envelope.Inputs, state.Variables, result.Completed, run.Effects, attempts); err != nil {
		return result, err
	}
	for stepID, evidence := range result.Completed {
		step := steps[stepID]
		if step.Bind != "" && evidence.Value != nil {
			result.Values[step.Bind] = *evidence.Value
		}
	}
	return result, nil
}

// validateResumeBusinessKeys reconstructs the same typed identity at each
// original plan boundary. Confirmed evidence supplies prior outputs; its own
// output cannot redefine the identity that was used before dispatch.
func validateResumeBusinessKeys(plan model.Plan, inputs, live map[string]model.Value, completed map[string]integration.StepResult, effects []*loadrun.Effect, attempts map[string]string) error {
	values := map[string]model.Value{}
	for name, value := range inputs {
		values["input."+name] = value
	}
	for _, binding := range plan.Bindings {
		if binding.Value != nil {
			values["binding."+binding.Name] = *binding.Value
		}
	}
	for name, value := range live {
		values["binding."+name] = value
	}
	byStep := map[string][]*loadrun.Effect{}
	for _, effect := range effects {
		if effect.AttemptId == nil || effect.State == nil || (*effect.State != "confirmed" && *effect.State != "absent") {
			return ErrNeedsReconciliation
		}
		stepID, exists := attempts[*effect.AttemptId]
		if !exists {
			return ErrNeedsReconciliation
		}
		byStep[stepID] = append(byStep[stepID], effect)
	}
	for _, step := range plan.Steps {
		evidence, completedStep := completed[step.ID]
		stepEffects := byStep[step.ID]
		if len(stepEffects) == 0 {
			if completedStep {
				return ErrNeedsReconciliation
			}
			continue
		}
		canonical, err := effectBusinessKey(plan, step, values)
		if err != nil {
			return ErrNeedsReconciliation
		}
		confirmed := 0
		for _, effect := range stepEffects {
			if effect.BusinessKey == nil || canonical != *effect.BusinessKey {
				return ErrNeedsReconciliation
			}
			if *effect.State == "absent" {
				var absence integration.StepResult
				if effect.EvidenceJson == nil || json.Unmarshal([]byte(*effect.EvidenceJson), &absence) != nil || absence.DispatchState != "notDispatched" {
					return ErrNeedsReconciliation
				}
				continue
			}
			confirmed++
		}
		if confirmed > 1 || completedStep != (confirmed == 1) {
			return ErrNeedsReconciliation
		}
		if completedStep {
			if evidence.VerificationState != "verified" {
				return ErrNeedsReconciliation
			}
			if step.Bind != "" && evidence.Value != nil {
				values["binding."+step.Bind] = *evidence.Value
			}
		}
	}
	return nil
}

// ValidateStateVariables checks binding identity and transitive provenance
// consumed by confirmed effects. StatePatch calls the locked helper under the
// same admission guard and user mutex as the generated write.
func (b *Builder) ValidateStateVariables(ctx context.Context, p auth.Principal, runID string, variables map[string]model.Value) error {
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	_, err = validateStateVariablesLocked(ctx, user.server, p, runID, variables)
	return err
}

func validateStateVariablesLocked(ctx context.Context, server *standalone.Server, p auth.Principal, runID string, variables map[string]model.Value) (State, error) {
	run, err := load(ctx, server, p, runID)
	if err != nil {
		return State{}, err
	}
	state, err := stateRead(ctx, server, p, runID)
	if err != nil {
		return State{}, err
	}
	if err = validateStateHistoryScope(run); err != nil {
		return State{}, err
	}
	if hasAncestorAttempts(run, state.PlanID) {
		envelope, err := decodeStatePlan(run)
		if err != nil {
			return State{}, err
		}
		snapshot, err := repairSnapshotLocked(ctx, server, p, runID, state.PlanID, envelope.Plan, envelope.Inputs)
		if err != nil {
			return State{}, err
		}
		if snapshot.Reference.Revision != state.Revision || snapshot.Reference.ObjectiveID != state.ObjectiveID || snapshot.Reference.ContentHash != *run.Plan.ContentHash {
			return State{}, errors.New("repair state reference changed")
		}
		if err = validateRepairedStateVariables(snapshot, variables); err != nil {
			return State{}, err
		}
	} else if err = validateStateVariableSnapshot(run, state.Variables, variables); err != nil {
		return State{}, err
	}
	return state, nil
}

// bindingReferences walks the serialized typed payload, never source text. A
// literal string that happens to contain "binding.x" is not a dependency.
func bindingReferences(payload any) (map[string]bool, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var value any
	if err = json.Unmarshal(encoded, &value); err != nil {
		return nil, err
	}
	result := map[string]bool{}
	var visit func(any)
	visit = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			if typed["kind"] == string(model.ReferenceValue) {
				if ref, ok := typed["ref"].(string); ok && strings.HasPrefix(ref, "binding.") {
					result[strings.TrimPrefix(ref, "binding.")] = true
				}
			}
			for _, child := range typed {
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(value)
	return result, nil
}

type statePlanEnvelope struct {
	Plan   model.Plan             `json:"plan"`
	Inputs map[string]model.Value `json:"inputs"`
}

func decodeStatePlan(run *loadrun.Run) (statePlanEnvelope, error) {
	var envelope statePlanEnvelope
	if run == nil || run.Plan == nil || run.Plan.ContentJson == nil || run.Plan.ContentHash == nil || run.PlanId == nil || run.Plan.Id == nil || *run.PlanId != *run.Plan.Id {
		return envelope, errors.New("immutable plan unavailable")
	}
	sum := sha256.Sum256([]byte(*run.Plan.ContentJson))
	if hex.EncodeToString(sum[:]) != *run.Plan.ContentHash {
		return envelope, errors.New("immutable plan content hash mismatch")
	}
	if err := json.Unmarshal([]byte(*run.Plan.ContentJson), &envelope); err != nil {
		return envelope, err
	}
	return envelope, envelope.Plan.Validate()
}

func validateStateHistoryScope(run *loadrun.Run) error {
	if run == nil || run.Namespace == nil || *run.Namespace == "" || run.Id == nil || *run.Id == "" {
		return ErrNeedsReconciliation
	}
	if run.Plan == nil || run.Plan.Namespace == nil || *run.Plan.Namespace != *run.Namespace {
		return ErrNeedsReconciliation
	}
	attemptIDs, effectIDs, effectAttempts := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, attempt := range run.Attempts {
		if attempt == nil || attempt.Namespace == nil || *attempt.Namespace != *run.Namespace || attempt.RunId == nil || *attempt.RunId != *run.Id || attempt.Id == nil || attempt.PlanId == nil || attempt.StepId == nil {
			return ErrNeedsReconciliation
		}
		if attemptIDs[*attempt.Id] {
			return ErrNeedsReconciliation
		}
		attemptIDs[*attempt.Id] = true
	}
	for _, effect := range run.Effects {
		if effect == nil || effect.Namespace == nil || *effect.Namespace != *run.Namespace || effect.RunId == nil || *effect.RunId != *run.Id || effect.Id == nil || effect.AttemptId == nil || effect.State == nil {
			return ErrNeedsReconciliation
		}
		if effectIDs[*effect.Id] || effectAttempts[*effect.AttemptId] || !attemptIDs[*effect.AttemptId] {
			return ErrNeedsReconciliation
		}
		effectIDs[*effect.Id], effectAttempts[*effect.AttemptId] = true, true
	}
	for id := range attemptIDs {
		if !effectAttempts[id] {
			return ErrNeedsReconciliation
		}
	}
	for _, milestone := range run.Milestones {
		if milestone == nil || milestone.Namespace == nil || *milestone.Namespace != *run.Namespace || milestone.RunId == nil || *milestone.RunId != *run.Id || milestone.AttemptId == nil || !attemptIDs[*milestone.AttemptId] || milestone.State == nil || *milestone.State != "verified" {
			return ErrNeedsReconciliation
		}
		for _, effect := range run.Effects {
			if *effect.AttemptId == *milestone.AttemptId && *effect.State != "confirmed" {
				return ErrNeedsReconciliation
			}
		}
	}
	return nil
}

func validateStateVariableSnapshot(run *loadrun.Run, live, variables map[string]model.Value) error {
	envelope, err := decodeStatePlan(run)
	if err != nil {
		return err
	}
	if err = validateStateHistoryScope(run); err != nil {
		return err
	}
	steps := map[string]model.Step{}
	for _, step := range envelope.Plan.Steps {
		steps[step.ID] = step
	}
	attempts := map[string]string{}
	for _, attempt := range run.Attempts {
		if *attempt.PlanId != *run.PlanId {
			return errors.New("ancestor state history requires verified repair lineage")
		}
		if _, exists := steps[*attempt.StepId]; !exists || attempts[*attempt.Id] != "" {
			return ErrNeedsReconciliation
		}
		attempts[*attempt.Id] = *attempt.StepId
	}
	completed := map[string]integration.StepResult{}
	for _, effect := range run.Effects {
		stepID, exists := attempts[*effect.AttemptId]
		if !exists || effect.EvidenceJson == nil {
			return ErrNeedsReconciliation
		}
		var evidence integration.StepResult
		if json.Unmarshal([]byte(*effect.EvidenceJson), &evidence) != nil || evidence.Value != nil && evidence.Value.Validate() != nil {
			return ErrNeedsReconciliation
		}
		switch *effect.State {
		case "absent":
			if evidence.DispatchState != "notDispatched" {
				return ErrNeedsReconciliation
			}
		case "confirmed":
			if evidence.VerificationState != "verified" {
				return ErrNeedsReconciliation
			}
			if _, exists := completed[stepID]; exists {
				return ErrNeedsReconciliation
			}
			if steps[stepID].Bind != "" && evidence.Value == nil {
				return ErrNeedsReconciliation
			}
			completed[stepID] = evidence
		default:
			return ErrNeedsReconciliation
		}
	}
	if err = validateResumeBusinessKeys(envelope.Plan, envelope.Inputs, live, completed, run.Effects, attempts); err != nil {
		return err
	}
	if err = validateStateBindingPolicy(envelope.Plan, envelope.Inputs, live, variables, completed); err != nil {
		return err
	}
	candidate := map[string]model.Value{}
	for name, value := range live {
		candidate[name] = value
	}
	for name, value := range variables {
		candidate[name] = value
	}
	// Known absence is not completed, but its original entity remains fixed.
	return validateResumeBusinessKeys(envelope.Plan, envelope.Inputs, candidate, completed, run.Effects, attempts)
}

func validateRepairedStateVariables(snapshot repairs.Snapshot, variables map[string]model.Value) error {
	if snapshot.Unknown || snapshot.Repair == nil {
		return ErrNeedsReconciliation
	}
	live := map[string]model.Value{}
	for name, value := range snapshot.Values {
		if strings.HasPrefix(name, "binding.") {
			live[strings.TrimPrefix(name, "binding.")] = value
		}
	}
	if err := validateStateBindingPolicy(snapshot.Plan, snapshot.Inputs, live, variables, snapshot.Completed); err != nil {
		return err
	}
	candidate := map[string]model.Value{}
	for name, value := range snapshot.Values {
		candidate[name] = value
	}
	for name, value := range variables {
		candidate["binding."+name] = value
	}
	steps := map[string]model.Step{}
	for _, step := range snapshot.Plan.Steps {
		steps[step.ID] = step
	}
	// Snapshot.Effects retains the verified source business-key declarations
	// mapped by admitted lineage. No historical attempt or plan ID is rewritten.
	for _, record := range snapshot.Effects {
		step, exists := steps[record.StepID]
		if !exists || record.State != "committed" && record.State != "absent" {
			return ErrNeedsReconciliation
		}
		step.Effect.BusinessKey = record.BusinessKey
		before, err := effectBusinessKey(snapshot.Plan, step, snapshot.Values)
		if err != nil {
			return ErrNeedsReconciliation
		}
		after, err := effectBusinessKey(snapshot.Plan, step, candidate)
		if err != nil || before != after {
			return ErrNeedsReconciliation
		}
	}
	return nil
}

func validateStateBindingPolicy(plan model.Plan, inputs, live, variables map[string]model.Value, completed map[string]integration.StepResult) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	bindings := map[string]model.Binding{}
	dependencies := map[string]map[string]bool{}
	for _, binding := range plan.Bindings {
		bindings[binding.Name] = binding
		refs, err := bindingReferences(binding)
		if err != nil {
			return err
		}
		dependencies[binding.Name] = refs
	}
	// Live alias references augment declared provenance rather than replacing it.
	for name, value := range live {
		if _, exists := bindings[name]; !exists {
			return errors.New("persisted variable absent from immutable plan")
		}
		refs, err := bindingReferences(value)
		if err != nil {
			return err
		}
		for ref := range refs {
			dependencies[name][ref] = true
		}
	}
	steps := map[string]model.Step{}
	for _, step := range plan.Steps {
		steps[step.ID] = step
		if step.Bind != "" {
			refs, err := bindingReferences(step)
			if err != nil {
				return err
			}
			if dependencies[step.Bind] == nil {
				return errors.New("step output absent from plan bindings")
			}
			for ref := range refs {
				dependencies[step.Bind][ref] = true
			}
		}
	}
	frozen := map[string]bool{}
	for stepID, evidence := range completed {
		step, exists := steps[stepID]
		if !exists || evidence.VerificationState != "verified" {
			return ErrNeedsReconciliation
		}
		refs, err := bindingReferences(step)
		if err != nil {
			return err
		}
		for ref := range refs {
			frozen[ref] = true
		}
		if step.Bind != "" {
			frozen[step.Bind] = true
		}
	}
	// Follow aliases and derived output provenance to a fixed point, including
	// references whose live value was materialized after the original dispatch.
	queue := make([]string, 0, len(frozen))
	for name := range frozen {
		queue = append(queue, name)
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if _, exists := bindings[name]; !exists {
			return errors.New("confirmed effect binding absent from immutable plan")
		}
		for ref := range dependencies[name] {
			if !frozen[ref] {
				frozen[ref] = true
				queue = append(queue, ref)
			}
		}
	}
	candidateValues := map[string]model.Value{}
	for name, value := range inputs {
		candidateValues["input."+name] = value
	}
	for name, binding := range bindings {
		if binding.Value != nil {
			candidateValues["binding."+name] = *binding.Value
		}
	}
	for name, value := range live {
		candidateValues["binding."+name] = value
	}
	for name, value := range variables {
		candidateValues["binding."+name] = value
	}
	for name, value := range variables {
		binding, exists := bindings[name]
		if !exists || binding.Type != "value" {
			return errors.New("state variable does not name a typed plan value binding")
		}
		if err := value.Validate(); err != nil {
			return err
		}
		if frozen[name] {
			return errors.New("binding already belongs to verified effect history; create an immutable repair revision")
		}
		if _, err := model.ResolveValue(value, candidateValues); err != nil {
			return errors.New("patched variable typed reference is unknown, cyclic or unavailable")
		}
	}
	return nil
}
