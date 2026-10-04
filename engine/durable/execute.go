package durable

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/beginattempt"
	"github.com/viant/mechanize/data/commitoutcome"
	"github.com/viant/mechanize/data/loadrun"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"reflect"
	"time"
)

// Execute is Endly's single-action callback. Intent durability precedes input;
// verified outcome persistence follows the external executor. Database hooks
// cannot call this executor and database retries cannot replay it.
func (b *Builder) Execute(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (integration.StepResult, error) {
	actual, authErr := auth.FromContext(ctx)
	if authErr != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return integration.StepResult{}, auth.ErrUnauthorized
	}
	metadata, ok := integration.ExecutionFromContext(ctx)
	if !ok || metadata.RunID == "" || metadata.PlanID == "" {
		return integration.StepResult{}, errors.New("durable execution metadata required")
	}
	epoch := 0
	var err error
	if step.Effect.Class != model.ReadOnly {
		ctx, epoch, err = b.prepareStepAuthority(ctx, p, step)
		if err != nil || epoch <= 0 {
			if err == nil {
				err = errors.New("held executor authority required")
			}
			return integration.StepResult{}, err
		}
	}
	ctx, user, err := b.bound(ctx, p, epoch)
	if err != nil {
		return integration.StepResult{}, err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	run, err := load(ctx, user.server, p, metadata.RunID)
	if err != nil {
		return integration.StepResult{}, err
	}
	if run.PlanId == nil || *run.PlanId != metadata.PlanID || run.Plan == nil || run.Plan.ContentJson == nil {
		return integration.StepResult{}, errors.New("immutable plan identity mismatch")
	}
	var envelope struct {
		Plan   model.Plan             `json:"plan"`
		Inputs map[string]model.Value `json:"inputs"`
	}
	if err = json.Unmarshal([]byte(*run.Plan.ContentJson), &envelope); err != nil {
		return integration.StepResult{}, errors.New("persisted plan is invalid")
	}
	if metadata.StepIndex < 0 || metadata.StepIndex >= len(envelope.Plan.Steps) || !reflect.DeepEqual(step, envelope.Plan.Steps[metadata.StepIndex]) {
		return integration.StepResult{}, errors.New("step differs from immutable durable plan")
	}
	for name, expected := range envelope.Inputs {
		actual, exists := values["input."+name]
		if !exists || !reflect.DeepEqual(actual, expected) {
			return integration.StepResult{}, errors.New("typed input differs from persisted plan input")
		}
	}
	if metadata.Resumed && !matchesResumedCorrelation(run, metadata) {
		return integration.StepResult{}, errors.New("resumed operation correlation differs from committed durable admission")
	}
	if hasAncestorAttempts(run, metadata.PlanID) {
		snapshot, err := repairSnapshotLocked(ctx, user.server, p, metadata.RunID, metadata.PlanID, envelope.Plan, envelope.Inputs)
		if err != nil {
			return integration.StepResult{}, err
		}
		if previous, complete := snapshot.Completed[step.ID]; complete {
			currentKey, err := effectBusinessKey(envelope.Plan, step, values)
			if err != nil {
				return integration.StepResult{}, err
			}
			matched, inherited := false, false
			for _, entry := range snapshot.Lineage {
				if entry.StepID == step.ID && entry.StepIndex == metadata.StepIndex && entry.State == "confirmed" {
					inherited = true
					matched = entry.BusinessKey == currentKey
				}
			}
			if inherited && (!matched || previous.VerificationState != "verified") {
				return integration.StepResult{}, ErrNeedsReconciliation
			}
			if inherited {
				return previous, nil
			}
		}
	}
	if step.Effect.Class == model.ReadOnly {
		return b.dispatchWhileLocked(data.WithoutCommittedStepIntent(ctx), p, user, step, values)
	}
	businessKey, keyErr := effectBusinessKey(envelope.Plan, step, values)
	if keyErr != nil {
		return integration.StepResult{}, keyErr
	}
	nextSequence := 1
	for _, event := range run.Events {
		if event.Sequence != nil && *event.Sequence >= nextSequence {
			nextSequence = *event.Sequence + 1
		}
	}
	attemptID, previous, err := admitStepAttempt(run, metadata, step, businessKey)
	if err != nil {
		return integration.StepResult{}, err
	}
	if previous != nil {
		return *previous, nil
	}
	// Lazy component compilation belongs before intent/input, not inside the
	// bounded final receipt write. This prepares metadata only: no handler or
	// writer invocation, placeholder outcome, or product-row change occurs.
	prepareCtx, prepareCancel := context.WithTimeout(ctx, time.Duration(step.TimeoutMs)*time.Millisecond)
	err = user.server.PrepareComponent(prepareCtx, spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/commitoutcome", Name: "CommitOutcome"})
	prepareCancel()
	if err != nil {
		return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, fmt.Errorf("outcome persistence preparation: %w", err)
	}
	effectID := key("effect", attemptID)
	if run.Revision == nil {
		return integration.StepResult{}, errors.New("durable run revision missing")
	}
	attempt := &beginattempt.Attempt{}
	attempt.SetNamespace(pointer(p.Namespace))
	attempt.SetId(pointer(attemptID))
	attempt.SetRunId(pointer(metadata.RunID))
	attempt.SetStepId(pointer(step.ID))
	attempt.SetPlanId(pointer(metadata.PlanID))
	attempt.SetLeaseEpoch(pointer(epoch))
	attempt.SetState(pointer("intent"))
	attempt.SetCreatedAt(pointer(now()))
	intent := &beginattempt.Intent{}
	intent.SetNamespace(pointer(p.Namespace))
	intent.SetId(pointer(effectID))
	intent.SetAttemptId(pointer(attemptID))
	intent.SetRunId(pointer(metadata.RunID))
	intent.SetBusinessKey(pointer(businessKey))
	intent.SetState(pointer("intent"))
	intent.SetRevision(pointer(1))
	attempt.SetIntents([]*beginattempt.Intent{intent})
	event := &beginattempt.Event{}
	event.SetNamespace(pointer(p.Namespace))
	event.SetId(pointer(key("intent-event", attemptID)))
	event.SetRunId(pointer(metadata.RunID))
	event.SetAttemptId(pointer(attemptID))
	event.SetSequence(pointer(nextSequence))
	event.SetKind(pointer("intent"))
	event.SetPayloadJson(pointer(`{}`))
	event.SetCreatedAt(pointer(now()))
	attempt.SetEvents([]*beginattempt.Event{event})
	beginRun := &beginattempt.Run{}
	beginRun.SetNamespace(pointer(p.Namespace))
	beginRun.SetId(pointer(metadata.RunID))
	beginRun.SetRevision(run.Revision)
	beginRun.SetUpdatedAt(pointer(now()))
	beginRun.SetAttempts([]*beginattempt.Attempt{attempt})
	begin := &beginattempt.BeginAttemptInput{}
	begin.SetNamespace(p.Namespace)
	begin.SetBeginAttempt([]*beginattempt.Run{beginRun})
	previousRevision := *run.Revision
	beginOutput, err := invoke(ctx, user.server, "beginattempt", "BeginAttempt", "PATCH", begin, true)
	if err != nil {
		return integration.StepResult{}, err
	}
	// Any panic/process interruption from here leaves an unresolved committed
	// intent. No generic retry may infer absence from a missing receipt.
	result := integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	committed := data.CommittedStepIntent{Namespace: p.Namespace, ClientID: p.ClientID, RunID: metadata.RunID, PlanID: metadata.PlanID, StepID: step.ID, StepIndex: metadata.StepIndex, AttemptID: attemptID, EffectID: effectID, LeaseEpoch: epoch, SessionID: metadata.SessionID, OperationID: metadata.OperationID}
	complete, dispatchErr := committedIntentFromBegin(beginOutput, previousRevision, &committed)
	if dispatchErr == nil && !complete {
		var actual *loadrun.Run
		actual, dispatchErr = load(ctx, user.server, p, metadata.RunID)
		if dispatchErr == nil {
			dispatchErr = committedIntentFromRun(actual, previousRevision, &committed)
		}
	}
	if dispatchErr == nil {
		var dispatchCtx context.Context
		var revoke func()
		dispatchCtx, revoke, dispatchErr = data.WithCommittedStepIntent(ctx, p, committed)
		if dispatchErr == nil {
			result, dispatchErr = func() (integration.StepResult, error) {
				defer revoke()
				return b.dispatchWhileLocked(dispatchCtx, p, user, step, values)
			}()
		}
	}
	if dispatchErr == nil && step.Postcondition != nil {
		postValues := make(map[string]model.Value, len(values)+1)
		for k, v := range values {
			postValues[k] = v
		}
		if step.Bind != "" && result.Value != nil {
			postValues["binding."+step.Bind] = *result.Value
		}
		verified, evalErr := b.evaluateWhileLocked(objective.WithObservationWait(ctx), p, user, *step.Postcondition, postValues)
		result.Postcondition = &verified
		if evalErr != nil || verified.Truth != objective.True {
			result.VerificationState = "unknown"
			dispatchErr = errors.Join(evalErr, errors.New("effect postcondition is not verified"))
		} else {
			// The enrolled evaluator independently validated authority, freshness
			// and read evidence. This verifies this explicit effect postcondition;
			// observational UI evidence does not establish business success.
			result.VerificationState = "verified"
		}
	}
	state := "unknown"
	if dispatchErr == nil && result.VerificationState == "verified" {
		state = "confirmed"
	} else if result.DispatchState == "notDispatched" {
		state = "absent"
	}
	evidence, err := json.Marshal(result)
	if err != nil {
		return result, errors.Join(dispatchErr, err)
	}
	effect := &commitoutcome.Effect{}
	effect.SetNamespace(pointer(p.Namespace))
	effect.SetId(pointer(effectID))
	effect.SetAttemptId(pointer(attemptID))
	effect.SetRunId(pointer(metadata.RunID))
	effect.SetRevision(pointer(1))
	effect.SetState(pointer(state))
	effect.SetEvidenceJson(pointer(string(evidence)))
	outcomeEvent := &commitoutcome.Event{}
	outcomeEvent.SetNamespace(pointer(p.Namespace))
	outcomeEvent.SetId(pointer(key("outcome-event", attemptID)))
	outcomeEvent.SetRunId(pointer(metadata.RunID))
	outcomeEvent.SetAttemptId(pointer(attemptID))
	outcomeEvent.SetSequence(pointer(nextSequence + 1))
	outcomeEvent.SetKind(pointer("outcome"))
	outcomeEvent.SetPayloadJson(pointer(string(evidence)))
	outcomeEvent.SetCreatedAt(pointer(now()))
	effect.SetEvents([]*commitoutcome.Event{outcomeEvent})
	if state == "confirmed" {
		milestone := &commitoutcome.Milestone{}
		milestone.SetNamespace(pointer(p.Namespace))
		milestone.SetId(pointer(key("milestone", metadata.RunID, step.ID)))
		milestone.SetRunId(pointer(metadata.RunID))
		milestone.SetAttemptId(pointer(attemptID))
		milestone.SetState(pointer("verified"))
		milestone.SetEvidenceJson(pointer(string(evidence)))
		effect.SetMilestones([]*commitoutcome.Milestone{milestone})
	}
	commit := &commitoutcome.CommitOutcomeInput{}
	commit.SetNamespace(p.Namespace)
	commit.SetCommitOutcome([]*commitoutcome.Effect{effect})
	// Cancellation inhibits input but must not discard evidence for an already
	// dispatched effect. Persist with the same identity under a bounded deadline.
	finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err = invoke(finalCtx, user.server, "commitoutcome", "CommitOutcome", "PATCH", commit, true); err != nil {
		return result, errors.Join(dispatchErr, fmt.Errorf("durable outcome: %w", err))
	}
	if state == "unknown" {
		return result, errors.Join(dispatchErr, ErrNeedsReconciliation)
	}
	return result, dispatchErr
}

func matchesResumedCorrelation(run *loadrun.Run, metadata integration.ExecutionMetadata) bool {
	return metadata.SessionID != "" && metadata.OperationID != "" && run.EndlySessionId != nil && run.EndlyOperationId != nil && *run.EndlySessionId == metadata.SessionID && *run.EndlyOperationId == metadata.OperationID
}

// admitStepAttempt inspects the immutable attempt relation before any write.
// Confirmed identity is adopted; global uncertainty is a barrier. Only a new,
// committed resumed operation can append an intent after proven non-dispatch.
func admitStepAttempt(run *loadrun.Run, metadata integration.ExecutionMetadata, step model.Step, businessKey string) (string, *integration.StepResult, error) {
	base := key("attempt", metadata.RunID, metadata.PlanID, step.ID)
	if metadata.Resumed && !matchesResumedCorrelation(run, metadata) {
		return "", nil, ErrNeedsReconciliation
	}
	attempts := map[string]*loadrun.Attempt{}
	for _, attempt := range run.Attempts {
		if attempt.Id == nil || attempt.PlanId == nil || attempt.StepId == nil {
			return "", nil, ErrNeedsReconciliation
		}
		if attempts[*attempt.Id] != nil {
			return "", nil, ErrNeedsReconciliation
		}
		attempts[*attempt.Id] = attempt
	}
	absent := false
	var confirmed *integration.StepResult
	for _, effect := range run.Effects {
		if effect.State == nil || (*effect.State != "confirmed" && *effect.State != "absent") {
			return "", nil, ErrNeedsReconciliation
		}
		if effect.AttemptId == nil || effect.Id == nil || *effect.Id != key("effect", *effect.AttemptId) {
			return "", nil, ErrNeedsReconciliation
		}
		attempt := attempts[*effect.AttemptId]
		if attempt == nil {
			return "", nil, ErrNeedsReconciliation
		}
		if *attempt.PlanId != metadata.PlanID || *attempt.StepId != step.ID {
			continue
		}
		if effect.BusinessKey == nil || *effect.BusinessKey != businessKey || effect.EvidenceJson == nil {
			return "", nil, ErrNeedsReconciliation
		}
		var evidence integration.StepResult
		if json.Unmarshal([]byte(*effect.EvidenceJson), &evidence) != nil {
			return "", nil, ErrNeedsReconciliation
		}
		if evidence.Value != nil && evidence.Value.Validate() != nil {
			return "", nil, ErrNeedsReconciliation
		}
		if *effect.State == "absent" {
			if evidence.DispatchState != "notDispatched" {
				return "", nil, ErrNeedsReconciliation
			}
			absent = true
			continue
		}
		if evidence.VerificationState != "verified" || confirmed != nil {
			return "", nil, ErrNeedsReconciliation
		}
		if evidence.Value != nil && evidence.Value.Validate() != nil {
			return "", nil, ErrNeedsReconciliation
		}
		if step.Bind != "" && evidence.Value == nil {
			return "", nil, ErrNeedsReconciliation
		}
		confirmed = &evidence
	}
	if confirmed != nil {
		return base, confirmed, nil
	}
	if metadata.Resumed && (run.Status == nil || *run.Status != "running") {
		return "", nil, ErrNeedsReconciliation
	}
	if !absent {
		if attempts[base] != nil {
			return "", nil, ErrNeedsReconciliation
		}
		return base, nil, nil
	}
	if !metadata.Resumed || run.Status == nil || *run.Status != "running" {
		return "", nil, ErrNeedsReconciliation
	}
	retry := key("attempt-resume", metadata.RunID, metadata.PlanID, step.ID, metadata.OperationID)
	// A repeated call in one resumed operation never creates another intent.
	if attempts[retry] != nil {
		return "", nil, ErrNeedsReconciliation
	}
	return retry, nil, nil
}

// Validate present output facts before considering a generated-read fallback.
// A contradictory commit result is never repaired by guessing a revision/ID.
func committedIntentFromBegin(output any, previousRevision int, record *data.CommittedStepIntent) (bool, error) {
	if output == nil {
		return false, nil
	}
	out, ok := output.(*beginattempt.BeginAttemptOutput)
	if !ok || out == nil {
		return false, errors.New("committed attempt output type invalid")
	}
	if len(out.Data) == 0 {
		return false, nil
	}
	if len(out.Data) != 1 || out.Data[0] == nil {
		return false, errors.New("committed attempt output root invalid")
	}
	root := out.Data[0]
	if root.Namespace != nil && *root.Namespace != record.Namespace || root.Id != nil && *root.Id != record.RunID || root.PlanId != nil && *root.PlanId != record.PlanID || root.Revision != nil && *root.Revision != previousRevision+1 {
		return false, errors.New("committed attempt output identity/revision mismatch")
	}
	complete := root.Namespace != nil && root.Id != nil && root.Revision != nil
	if root.EndlySessionId != nil && *root.EndlySessionId != record.SessionID || root.EndlyOperationId != nil && *root.EndlyOperationId != record.OperationID {
		return false, errors.New("committed attempt output correlation mismatch")
	}
	if len(root.Attempts) == 0 {
		return false, nil
	}
	if len(root.Attempts) != 1 || root.Attempts[0] == nil {
		return false, errors.New("committed attempt output graph invalid")
	}
	a := root.Attempts[0]
	if a.Namespace != nil && *a.Namespace != record.Namespace || a.Id != nil && *a.Id != record.AttemptID || a.RunId != nil && *a.RunId != record.RunID || a.PlanId != nil && *a.PlanId != record.PlanID || a.StepId != nil && *a.StepId != record.StepID || a.LeaseEpoch != nil && *a.LeaseEpoch != record.LeaseEpoch || a.State != nil && *a.State != "intent" {
		return false, errors.New("committed attempt output attempt mismatch")
	}
	complete = complete && a.Namespace != nil && a.Id != nil && a.RunId != nil && a.PlanId != nil && a.StepId != nil && a.LeaseEpoch != nil && a.State != nil
	if len(a.Intents) == 0 {
		return false, nil
	}
	if len(a.Intents) != 1 || a.Intents[0] == nil {
		return false, errors.New("committed attempt output effect graph invalid")
	}
	effect := a.Intents[0]
	if effect.Namespace != nil && *effect.Namespace != record.Namespace || effect.Id != nil && *effect.Id != record.EffectID || effect.AttemptId != nil && *effect.AttemptId != record.AttemptID || effect.RunId != nil && *effect.RunId != record.RunID || effect.State != nil && *effect.State != "intent" || effect.Revision != nil && *effect.Revision != 1 {
		return false, errors.New("committed attempt output effect mismatch")
	}
	complete = complete && effect.Namespace != nil && effect.Id != nil && effect.AttemptId != nil && effect.RunId != nil && effect.State != nil && effect.Revision != nil
	if complete {
		record.RunRevision = *root.Revision
	}
	return complete, nil
}
func committedIntentFromRun(run *loadrun.Run, previousRevision int, record *data.CommittedStepIntent) error {
	if run == nil || run.Namespace == nil || *run.Namespace != record.Namespace || run.Id == nil || *run.Id != record.RunID || run.PlanId == nil || *run.PlanId != record.PlanID || run.Revision == nil || *run.Revision != previousRevision+1 {
		return errors.New("committed attempt readback root mismatch")
	}
	attempts, effects := 0, 0
	for _, a := range run.Attempts {
		if a != nil && a.Id != nil && *a.Id == record.AttemptID {
			attempts++
			if a.Namespace == nil || *a.Namespace != record.Namespace || a.RunId == nil || *a.RunId != record.RunID || a.PlanId == nil || *a.PlanId != record.PlanID || a.StepId == nil || *a.StepId != record.StepID || a.LeaseEpoch == nil || *a.LeaseEpoch != record.LeaseEpoch || a.State == nil || *a.State != "intent" {
				return errors.New("committed attempt readback attempt mismatch")
			}
		}
	}
	for _, e := range run.Effects {
		if e != nil && e.Id != nil && *e.Id == record.EffectID {
			effects++
			if e.Namespace == nil || *e.Namespace != record.Namespace || e.RunId == nil || *e.RunId != record.RunID || e.AttemptId == nil || *e.AttemptId != record.AttemptID || e.State == nil || *e.State != "intent" || e.Revision == nil || *e.Revision != 1 {
				return errors.New("committed attempt readback effect mismatch")
			}
		}
	}
	if attempts != 1 || effects != 1 {
		return errors.New("committed attempt readback graph incomplete")
	}
	record.RunRevision = *run.Revision
	return nil
}
