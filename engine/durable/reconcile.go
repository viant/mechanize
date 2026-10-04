package durable

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/datly/spec"
	"reflect"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/data/reconcileeffect"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

type EffectReconcileRequest struct {
	RunID                  string `json:"runId"`
	PlanID                 string `json:"planId"`
	AttemptID              string `json:"attemptId"`
	EffectID               string `json:"effectId"`
	ExpectedRunRevision    int    `json:"expectedRunRevision"`
	ExpectedEffectRevision int    `json:"expectedEffectRevision"`
	RequestID              string `json:"requestId"`
}
type EffectReconcileResult struct {
	CommitConfirmed bool                   `json:"commitConfirmed"`
	EffectID        string                 `json:"effectId"`
	State           string                 `json:"state"`
	ContractID      string                 `json:"contractId,omitempty"`
	Reason          string                 `json:"reason,omitempty"`
	Run             ReconciliationRunState `json:"run"`
}

type ReconciliationRunState struct {
	RunID                  string   `json:"runId"`
	PlanID                 string   `json:"planId"`
	Revision               int      `json:"revision"`
	Status                 string   `json:"status"`
	NeedsAttention         bool     `json:"needsAttention"`
	UnresolvedEffectIDs    []string `json:"unresolvedEffectIds"`
	UnresolvedCount        int      `json:"unresolvedCount"`
	UnresolvedIDsTruncated bool     `json:"unresolvedIdsTruncated"`
}

func reconciliationRunState(s State) ReconciliationRunState {
	r := ReconciliationRunState{RunID: s.RunID, PlanID: s.PlanID, Revision: s.Revision, Status: s.Status, NeedsAttention: s.NeedsAttention || len(s.UnresolvedEffects) > 0, UnresolvedEffectIDs: []string{}}
	r.UnresolvedCount = len(s.UnresolvedEffects)
	for _, effect := range s.UnresolvedEffects {
		if effect.Id != nil {
			if len(r.UnresolvedEffectIDs) == 32 {
				r.UnresolvedIDsTruncated = true
				break
			}
			r.UnresolvedEffectIDs = append(r.UnresolvedEffectIDs, *effect.Id)
		}
	}
	return r
}

func (r EffectReconcileRequest) validate() error {
	for _, v := range []string{r.RunID, r.PlanID, r.AttemptID, r.EffectID, r.RequestID} {
		if strings.TrimSpace(v) == "" || len(v) > 256 || strings.ContainsAny(v, "\r\n\x00") {
			return errors.New("bounded exact reconciliation identity required")
		}
	}
	if r.ExpectedRunRevision < 1 || r.ExpectedEffectRevision < 1 {
		return errors.New("expected run and effect revisions required")
	}
	return nil
}

// ReconcileEffect evaluates only an enrolled read contract. It never calls the
// external executor, edits the original plan, or resumes a workflow.
func (b *Builder) ReconcileEffect(ctx context.Context, p auth.Principal, req EffectReconcileRequest) (result EffectReconcileResult, resultErr error) {
	if err := req.validate(); err != nil {
		return EffectReconcileResult{}, err
	}
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return EffectReconcileResult{}, err
	}
	if b.options.ReconciliationGuard == nil || b.options.ResolveReconciliation == nil {
		return EffectReconcileResult{}, errors.New("qualified reconciliation integration unavailable")
	}
	release, err := b.options.ReconciliationGuard(ctx, p, req.RunID)
	if err != nil {
		return EffectReconcileResult{}, err
	}
	if release == nil {
		return EffectReconcileResult{}, errors.New("stopped executor guard unavailable")
	}
	defer func() {
		if cleanupErr := release(); cleanupErr != nil {
			resultErr = errors.Join(resultErr, cleanupErr)
			result.Reason = "reconciliation guard cleanup unconfirmed"
		}
	}()
	user.mu.Lock()
	defer user.mu.Unlock()
	run, err := load(ctx, user.server, p, req.RunID)
	if err != nil {
		return EffectReconcileResult{}, err
	}
	auditID := key("reconcile-event", p.Namespace, req.RunID, req.EffectID, req.RequestID)
	if contractID, committed, err := reconciledReadback(run, req, auditID); err != nil {
		return EffectReconcileResult{}, err
	} else if committed {
		state, err := stateRead(ctx, user.server, p, req.RunID)
		return EffectReconcileResult{CommitConfirmed: true, EffectID: req.EffectID, State: "confirmed", ContractID: contractID, Run: reconciliationRunState(state)}, err
	}
	c, effect, err := reconciliationContext(run, req)
	if err != nil {
		return EffectReconcileResult{}, err
	}
	state, err := stateRead(ctx, user.server, p, req.RunID)
	if err != nil {
		return EffectReconcileResult{}, err
	}
	for name, value := range state.Variables {
		c.Values["binding."+name] = value
	}
	actualKey, err := effectBusinessKey(c.Plan, c.Step, c.Values)
	if err != nil || actualKey != c.BusinessKey {
		return EffectReconcileResult{}, ErrNeedsReconciliation
	}
	// This callback is host code; no MCP input can provide a predicate or proof.
	contract, err := b.options.ResolveReconciliation(ctx, p, c)
	if err != nil {
		return EffectReconcileResult{EffectID: req.EffectID, State: "unknown", Reason: "no qualified reconciliation contract", Run: reconciliationRunState(state)}, err
	}
	hash, err := contract.Hash()
	if err != nil {
		return EffectReconcileResult{}, err
	}
	// Resolve the generated writer before obtaining time-sensitive evidence.
	// Preparation does not invoke it or mutate any row.
	prepareCtx, prepareCancel := context.WithTimeout(ctx, 30*time.Second)
	err = user.server.PrepareComponent(prepareCtx, spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/reconcileeffect", Name: "ReconcileEffect"})
	prepareCancel()
	if err != nil {
		return EffectReconcileResult{}, err
	}
	verified, err := b.evaluateWhileLocked(ctx, p, user, contract.Predicate, c.Values)
	if err != nil {
		return EffectReconcileResult{}, err
	}
	if verified.Truth != objective.True {
		return EffectReconcileResult{EffectID: req.EffectID, State: "unknown", ContractID: contract.ID, Reason: "fresh evidence did not establish the effect", Run: reconciliationRunState(state)}, nil
	}
	late := c.Original
	late.Observation = nil // Preserve the original tree in its original audit only.
	late.VerificationState = "verified"
	late.Postcondition = &verified
	stepHash, err := data.ReconcileEffectStepHash(c.Step)
	if err != nil {
		return EffectReconcileResult{}, err
	}
	sequence := 1
	for _, event := range run.Events {
		if event.Sequence == nil {
			return EffectReconcileResult{}, ErrNeedsReconciliation
		}
		if *event.Sequence >= sequence {
			sequence = *event.Sequence + 1
		}
	}
	ctx, err = data.WithStateMutationPermit(ctx, p.Namespace, req.RunID)
	if err != nil {
		return EffectReconcileResult{}, err
	}
	a := data.ReconcileEffectAuthority{Namespace: p.Namespace, RunID: req.RunID, PlanID: req.PlanID, StepID: c.Step.ID, AttemptID: req.AttemptID, EffectID: req.EffectID, BusinessKey: c.BusinessKey, OriginalStepHash: stepHash, OriginalEvidenceJSON: *effect.EvidenceJson, AuditID: key("reconcile-event", p.Namespace, req.RunID, req.EffectID, req.RequestID), MilestoneID: key("milestone", req.RunID, c.Step.ID), RunRevision: req.ExpectedRunRevision, EffectRevision: req.ExpectedEffectRevision, AuditSequence: sequence, Now: now(), Evidence: data.ReconcileEffectEvidence{ContractID: contract.ID, ContractHash: hash, RequiredAuthority: objective.Authority(contract.Predicate.RequiredAuthority), FreshnessMs: contract.Predicate.FreshnessMs, Result: verified, StepResult: late}}
	ctx, err = data.WithReconcileEffectAuthority(ctx, a)
	if err != nil {
		return EffectReconcileResult{}, err
	}
	a, err = data.RequireReconcileEffectAuthority(ctx)
	if err != nil {
		return EffectReconcileResult{}, err
	}
	input := reconciliationInput(a)
	if _, err = invoke(ctx, user.server, "reconcileeffect", "ReconcileEffect", "PATCH", input, true); err != nil {
		return EffectReconcileResult{}, err
	}
	updated, err := stateRead(ctx, user.server, p, req.RunID)
	if err != nil {
		return EffectReconcileResult{CommitConfirmed: true, EffectID: req.EffectID, State: "confirmed", ContractID: contract.ID, Reason: "reconciliation committed; state readback unavailable"}, err
	}
	updated.NeedsAttention = len(updated.UnresolvedEffects) > 0
	return EffectReconcileResult{CommitConfirmed: true, EffectID: req.EffectID, State: "confirmed", ContractID: contract.ID, Run: reconciliationRunState(updated)}, nil
}

// An identical request after a lost reply reads the committed audit; it never
// invokes the evaluator or writer again, nor replays the original action.
func reconciledReadback(run *loadrun.Run, req EffectReconcileRequest, auditID string) (string, bool, error) {
	var event *loadrun.Event
	for _, candidate := range run.Events {
		if candidate.Id != nil && *candidate.Id == auditID {
			if event != nil {
				return "", false, ErrNeedsReconciliation
			}
			event = candidate
		}
	}
	if event == nil {
		return "", false, nil
	}
	if event.Kind == nil || *event.Kind != "effect_reconciliation" || event.RunId == nil || *event.RunId != req.RunID || event.AttemptId == nil || *event.AttemptId != req.AttemptID || event.PayloadJson == nil {
		return "", false, ErrNeedsReconciliation
	}
	var proof data.ReconcileEffectAudit
	if json.Unmarshal([]byte(*event.PayloadJson), &proof) != nil || proof.RunID != req.RunID || proof.PlanID != req.PlanID || proof.AttemptID != req.AttemptID || proof.EffectID != req.EffectID || proof.PriorRunRevision != req.ExpectedRunRevision || proof.PriorEffectRevision != req.ExpectedEffectRevision {
		return "", false, ErrNeedsReconciliation
	}
	if run.PlanId == nil || *run.PlanId != req.PlanID || run.Plan == nil || run.Plan.ContentJson == nil || run.Plan.ContentHash == nil || data.ReconcileEffectHash([]byte(*run.Plan.ContentJson)) != *run.Plan.ContentHash {
		return "", false, ErrNeedsReconciliation
	}
	var envelope struct {
		Plan model.Plan `json:"plan"`
	}
	if json.Unmarshal([]byte(*run.Plan.ContentJson), &envelope) != nil {
		return "", false, ErrNeedsReconciliation
	}
	stepMatches := 0
	for _, step := range envelope.Plan.Steps {
		if step.ID == proof.StepID {
			hash, err := data.ReconcileEffectStepHash(step)
			if err != nil || hash != proof.OriginalStepHash {
				return "", false, ErrNeedsReconciliation
			}
			stepMatches++
		}
	}
	effectMatches := 0
	for _, effect := range run.Effects {
		if effect.Id != nil && *effect.Id == req.EffectID {
			if effect.State == nil || *effect.State != "confirmed" || effect.Revision == nil || *effect.Revision != req.ExpectedEffectRevision+1 || effect.AttemptId == nil || *effect.AttemptId != req.AttemptID || effect.EvidenceJson == nil || effect.BusinessKey == nil || *effect.BusinessKey != proof.BusinessKey {
				return "", false, ErrNeedsReconciliation
			}
			var receipt integration.StepResult
			if json.Unmarshal([]byte(*effect.EvidenceJson), &receipt) != nil || receipt.VerificationState != "verified" || !reflect.DeepEqual(receipt, proof.Evidence.StepResult) {
				return "", false, ErrNeedsReconciliation
			}
			effectMatches++
		}
	}
	milestoneMatches := 0
	for _, m := range run.Milestones {
		if m.Id != nil && *m.Id == key("milestone", req.RunID, proof.StepID) {
			if m.AttemptId == nil || *m.AttemptId != req.AttemptID || m.State == nil || *m.State != "verified" {
				return "", false, ErrNeedsReconciliation
			}
			milestoneMatches++
		}
	}
	if stepMatches != 1 || effectMatches != 1 || milestoneMatches != 1 {
		return "", false, ErrNeedsReconciliation
	}
	return proof.Evidence.ContractID, true, nil
}

func reconciliationContext(run *loadrun.Run, req EffectReconcileRequest) (ReconciliationContext, *loadrun.Effect, error) {
	var c ReconciliationContext
	if run == nil || run.Id == nil || *run.Id != req.RunID || run.PlanId == nil || *run.PlanId != req.PlanID || run.Revision == nil || *run.Revision != req.ExpectedRunRevision || run.Plan == nil || run.Plan.ContentJson == nil || run.Plan.ContentHash == nil || data.ReconcileEffectHash([]byte(*run.Plan.ContentJson)) != *run.Plan.ContentHash {
		return c, nil, ErrNeedsReconciliation
	}
	if run.Status == nil || (*run.Status != "running" && *run.Status != "paused" && *run.Status != "new") {
		return c, nil, ErrNeedsReconciliation
	}
	var envelope struct {
		Plan   model.Plan             `json:"plan"`
		Inputs map[string]model.Value `json:"inputs"`
	}
	if json.Unmarshal([]byte(*run.Plan.ContentJson), &envelope) != nil || envelope.Plan.Validate() != nil {
		return c, nil, ErrNeedsReconciliation
	}
	var attempt *loadrun.Attempt
	for _, a := range run.Attempts {
		if a.Id != nil && *a.Id == req.AttemptID {
			if attempt != nil {
				return c, nil, ErrNeedsReconciliation
			}
			attempt = a
		}
	}
	if attempt == nil || attempt.PlanId == nil || *attempt.PlanId != req.PlanID || attempt.RunId == nil || *attempt.RunId != req.RunID || attempt.StepId == nil {
		return c, nil, ErrNeedsReconciliation
	}
	var found bool
	for _, step := range envelope.Plan.Steps {
		if step.ID == *attempt.StepId {
			if found {
				return c, nil, ErrNeedsReconciliation
			}
			c.Step = step
			found = true
		}
	}
	if !found || req.EffectID != key("effect", req.AttemptID) {
		return c, nil, ErrNeedsReconciliation
	}
	var effect *loadrun.Effect
	for _, e := range run.Effects {
		if e.Id != nil && *e.Id == req.EffectID {
			if effect != nil {
				return c, nil, ErrNeedsReconciliation
			}
			effect = e
		}
	}
	if effect == nil || effect.RunId == nil || *effect.RunId != req.RunID || effect.AttemptId == nil || *effect.AttemptId != req.AttemptID || effect.Revision == nil || *effect.Revision != req.ExpectedEffectRevision || effect.State == nil || (*effect.State != "unknown" && *effect.State != "intent") || effect.EvidenceJson == nil || effect.BusinessKey == nil {
		return c, nil, ErrNeedsReconciliation
	}
	if json.Unmarshal([]byte(*effect.EvidenceJson), &c.Original) != nil {
		return c, nil, ErrNeedsReconciliation
	}
	// Only the immutable original outcome is eligible. A missing outcome needs an
	// independently qualified intent-adoption route, not a manufactured receipt.
	originalEvents := 0
	for _, event := range run.Events {
		if event.Id != nil && *event.Id == key("outcome-event", req.AttemptID) {
			if event.Kind == nil || *event.Kind != "outcome" || event.RunId == nil || *event.RunId != req.RunID || event.Sequence == nil || *event.Sequence < 1 || event.AttemptId == nil || *event.AttemptId != req.AttemptID || event.PayloadJson == nil || *event.PayloadJson != *effect.EvidenceJson {
				return c, nil, ErrNeedsReconciliation
			}
			originalEvents++
		}
	}
	if originalEvents != 1 {
		return c, nil, ErrNeedsReconciliation
	}
	c.RunID = req.RunID
	c.PlanID = req.PlanID
	c.AttemptID = req.AttemptID
	c.EffectID = req.EffectID
	c.BusinessKey = *effect.BusinessKey
	c.Plan = envelope.Plan
	c.Values = map[string]model.Value{}
	for name, value := range envelope.Inputs {
		c.Values["input."+name] = value
	}
	for _, binding := range c.Plan.Bindings {
		if binding.Value != nil {
			c.Values["binding."+binding.Name] = *binding.Value
		}
	}
	return c, effect, nil
}

func reconciliationInput(a data.ReconcileEffectAuthority) *reconcileeffect.ReconcileEffectInput {
	m := &reconcileeffect.Milestone{}
	m.SetNamespace(pointer(a.Namespace))
	m.SetId(pointer(a.MilestoneID))
	m.SetRunId(pointer(a.RunID))
	m.SetAttemptId(pointer(a.AttemptID))
	m.SetState(pointer("verified"))
	m.SetEvidenceJson(pointer(a.EvidenceJSON))
	e := &reconcileeffect.Effect{}
	e.SetNamespace(pointer(a.Namespace))
	e.SetId(pointer(a.EffectID))
	e.SetRunId(pointer(a.RunID))
	e.SetAttemptId(pointer(a.AttemptID))
	e.SetBusinessKey(pointer(a.BusinessKey))
	e.SetRevision(pointer(a.EffectRevision))
	e.SetState(pointer("confirmed"))
	e.SetEvidenceJson(pointer(a.EvidenceJSON))
	e.SetMilestones([]*reconcileeffect.Milestone{m})
	event := &reconcileeffect.Event{}
	event.SetNamespace(pointer(a.Namespace))
	event.SetId(pointer(a.AuditID))
	event.SetRunId(pointer(a.RunID))
	event.SetAttemptId(pointer(a.AttemptID))
	event.SetSequence(pointer(a.AuditSequence))
	event.SetKind(pointer("effect_reconciliation"))
	event.SetPayloadJson(pointer(a.AuditPayloadJSON))
	event.SetCreatedAt(pointer(a.Now))
	r := &reconcileeffect.Run{}
	r.SetNamespace(pointer(a.Namespace))
	r.SetId(pointer(a.RunID))
	r.SetRevision(pointer(a.RunRevision))
	r.SetStatus(pointer("paused"))
	r.SetUpdatedAt(pointer(a.Now))
	r.SetEffects([]*reconcileeffect.Effect{e})
	r.SetEvents([]*reconcileeffect.Event{event})
	in := &reconcileeffect.ReconcileEffectInput{}
	in.SetNamespace(a.Namespace)
	in.SetReconcileEffect([]*reconcileeffect.Run{r})
	return in
}
