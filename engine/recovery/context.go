package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	core "github.com/viant/mechanize/recovery"
)

type ContextRequest struct {
	RunID            string `json:"runId"`
	ExpectedRevision int    `json:"expectedRevision"`
	ExpectedPlanID   string `json:"expectedPlanId"`
}
type PlanningContext struct {
	Reference  RunReference `json:"reference"`
	IncidentID string       `json:"incidentId"`
	// Hashes describe the original private plan; the view below is redacted.
	BaseHash      string               `json:"baseHash"`
	ObjectiveHash string               `json:"objectiveHash"`
	View          core.RecoveryContext `json:"view"`
	Redacted      bool                 `json:"redacted"`
}
type ContextResult struct {
	Status    string           `json:"status"`
	Reason    string           `json:"reason,omitempty"`
	Reference *RunReference    `json:"reference,omitempty"`
	Context   *PlanningContext `json:"context,omitempty"`
}

func attention(reason string) ContextResult {
	return ContextResult{Status: "needsAttention", Reason: reason}
}
func expected(snapshot Snapshot, request ContextRequest) error {
	if request.ExpectedRevision <= 0 || request.ExpectedPlanID == "" || snapshot.Reference.RunID != request.RunID || snapshot.Reference.Revision != request.ExpectedRevision || snapshot.Reference.PlanID != request.ExpectedPlanID {
		return errors.New("exact owned run/plan/revision changed")
	}
	if snapshot.Reference.Status != "paused" && snapshot.Reference.Status != "new" {
		return errors.New("repair requires a stopped paused/new durable boundary")
	}
	if snapshot.Unknown {
		return errors.New("unknown effect must be reconciled durably before repair")
	}
	return nil
}
func (s *Service) Context(ctx context.Context, p auth.Principal, request ContextRequest) (ContextResult, error) {
	actual, bindErr := s.bound(ctx, p)
	if bindErr != nil {
		return attention("verified recovery identity unavailable"), bindErr
	}
	p = actual
	snapshot, err := s.Snapshot(ctx, p, request.RunID)
	if err != nil {
		return attention("owned durable context unavailable"), err
	}
	ref := snapshot.Reference
	if err = expected(snapshot, request); err != nil {
		return ContextResult{Status: "needsAttention", Reason: err.Error(), Reference: &ref}, nil
	}
	private, evidence, err := s.prepare(ctx, p, snapshot)
	if err != nil {
		return ContextResult{Status: "needsAttention", Reason: err.Error(), Reference: &ref}, nil
	}
	view, err := redact(private, snapshot)
	if err != nil {
		return ContextResult{Status: "needsAttention", Reason: err.Error(), Reference: &ref}, nil
	}
	_ = evidence
	return ContextResult{Status: "ready", Reference: &ref, Context: &PlanningContext{Reference: ref, IncidentID: snapshot.IncidentID, BaseHash: ref.PlanHash, ObjectiveHash: ref.ObjectiveHash, View: view, Redacted: true}}, nil
}
func (s *Service) prepare(ctx context.Context, p auth.Principal, snapshot Snapshot) (core.RecoveryContext, Evidence, error) {
	empty := core.RecoveryContext{}
	if s.options.PrepareEvidence == nil || s.options.VerifyEvidence == nil {
		return empty, Evidence{}, errors.New("trusted fresh observation, evidence and qualified recovery contracts unavailable")
	}
	detached, err := cloneSnapshot(snapshot)
	if err != nil {
		return empty, Evidence{}, err
	}
	evidence, err := s.options.PrepareEvidence(ctx, p, detached)
	if err != nil {
		return empty, evidence, err
	}
	evidence, err = cloneEvidence(evidence)
	if err != nil {
		return empty, evidence, err
	}
	now := time.Now()
	if !evidence.Verified || !evidence.Redacted || evidence.PolicyHash == "" || len(evidence.PolicyHash) > 128 || evidence.ValidUntil.Before(now) || evidence.ValidUntil.After(now.Add(5*time.Second)) || evidence.Observation.Ended.IsZero() || evidence.Observation.Ended.After(now) || now.Sub(evidence.Observation.Ended) > 5*time.Second || evidence.Observation.Truncated || len(evidence.Observation.Nodes) > 256 || len(evidence.Contracts) == 0 || len(evidence.Contracts) > 1000 || len(evidence.EvidenceRefs) == 0 || len(evidence.EvidenceRefs) > 128 {
		return empty, evidence, errors.New("verified redacted complete fresh bounded recovery evidence required")
	}
	allowed := false
	for _, surface := range surfaces(snapshot.Plan) {
		if evidence.Observation.Surface == surface {
			allowed = true
		}
	}
	if !allowed {
		return empty, evidence, errors.New("observation does not belong to immutable objective surface")
	}
	if err = s.options.VerifyEvidence(ctx, p, snapshot, evidence); err != nil {
		return empty, evidence, err
	}
	workflow, incident, err := s.budgets(snapshot)
	if err != nil {
		return empty, evidence, err
	}
	result := core.RecoveryContext{Namespace: p.Namespace, Base: snapshot.Plan, CompletedSteps: snapshot.CompletedSteps, ObjectiveHash: snapshot.Reference.ObjectiveHash, Bindings: snapshot.Values, Effects: snapshot.Effects, Contracts: evidence.Contracts, IncidentBudget: incident, WorkflowBudget: workflow, Observation: evidence.Observation, EvidenceRefs: append([]string(nil), evidence.EvidenceRefs...), Now: now}
	return result, evidence, nil
}
func (s *Service) budgets(snapshot Snapshot) (core.Budget, core.Budget, error) {
	if snapshot.Plan.Objective == nil || snapshot.Plan.Constraints == nil || snapshot.Plan.Recovery == nil || snapshot.Plan.Recovery.OnUnknownEffect != "needsAttention" {
		return core.Budget{}, core.Budget{}, errors.New("immutable objective/constraints and explicit recovery policy required")
	}
	policy := snapshot.Plan.Recovery
	workflow := core.Budget{MaxRepairs: policy.MaxRepairs, MaxElapsedMs: policy.MaxElapsedMs}
	if old := snapshot.Raw.Workflow; old != nil {
		if old.MaxRepairs == nil || old.UsedRepairs == nil || old.MaxElapsedMs == nil || old.ElapsedMs == nil || *old.MaxRepairs != policy.MaxRepairs || int64(*old.MaxElapsedMs) != policy.MaxElapsedMs {
			return workflow, core.Budget{}, errors.New("workflow budget policy mismatch")
		}
		workflow.UsedRepairs = *old.UsedRepairs
		workflow.ElapsedMs = int64(*old.ElapsedMs)
	}
	maxRepairs := s.options.IncidentMaxRepairs
	if maxRepairs > workflow.MaxRepairs {
		maxRepairs = workflow.MaxRepairs
	}
	maxMs := s.options.IncidentMaxElapsedMs
	if maxMs > workflow.MaxElapsedMs {
		maxMs = workflow.MaxElapsedMs
	}
	incident := core.Budget{MaxRepairs: maxRepairs, MaxElapsedMs: maxMs}
	for _, old := range snapshot.Raw.Incidents {
		if old.Id != nil && *old.Id == snapshot.IncidentID {
			if old.MaxRepairs == nil || old.UsedRepairs == nil || old.MaxElapsedMs == nil || old.ElapsedMs == nil || *old.MaxRepairs != maxRepairs || int64(*old.MaxElapsedMs) != maxMs {
				return workflow, incident, errors.New("incident budget policy mismatch")
			}
			incident.UsedRepairs = *old.UsedRepairs
			incident.ElapsedMs = int64(*old.ElapsedMs)
		}
	}
	valid := func(b core.Budget) bool {
		return b.MaxRepairs > 0 && b.MaxRepairs <= 10 && b.UsedRepairs >= 0 && b.UsedRepairs < b.MaxRepairs && b.MaxElapsedMs > 0 && b.MaxElapsedMs <= 3600000 && b.ElapsedMs >= 0 && b.ElapsedMs < b.MaxElapsedMs
	}
	if !valid(workflow) || !valid(incident) {
		return workflow, incident, errors.New("finite incident/workflow repair budget exhausted")
	}
	return workflow, incident, nil
}
func cloneSnapshot(snapshot Snapshot) (Snapshot, error) {
	body, err := json.Marshal(snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	var detached Snapshot
	err = json.Unmarshal(body, &detached)
	return detached, err
}
func cloneEvidence(evidence Evidence) (Evidence, error) {
	body, err := json.Marshal(evidence)
	if err != nil {
		return Evidence{}, err
	}
	var detached Evidence
	err = json.Unmarshal(body, &detached)
	return detached, err
}
func redact(private core.RecoveryContext, snapshot Snapshot) (core.RecoveryContext, error) {
	body, err := json.Marshal(private)
	if err != nil {
		return core.RecoveryContext{}, err
	}
	var out core.RecoveryContext
	if err = json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	// Binding/input values and outcome result values never cross the planner boundary.
	out.Bindings = map[string]model.Value{}
	for name, definition := range out.Base.Inputs {
		if definition.Sensitive {
			definition.Default = nil
			out.Base.Inputs[name] = definition
		}
	}
	out.Observation.Epoch = ""
	out.Observation.Surface.TabID = ""
	out.Observation.Surface.Title = ""
	for i := range out.Observation.Nodes {
		out.Observation.Nodes[i].Ref = model.ElementRef{}
		out.Observation.Nodes[i].ParentID = ""
		out.Observation.Nodes[i].Values = nil
	}
	// A legacy plan containing a literal known secret cannot be safely proposed
	// without rewriting protected fields. Stop rather than exposing it or pretending
	// an opaque planner token is a new input/authority.
	secrets := []model.Value{}
	for name, definition := range snapshot.Plan.Inputs {
		if definition.Sensitive {
			if value, ok := snapshot.Inputs[name]; ok {
				secrets = append(secrets, value)
			}
			if definition.Default != nil {
				secrets = append(secrets, *definition.Default)
			}
		}
	}
	var scan func(reflect.Value) bool
	vt := reflect.TypeOf(model.Value{})
	scan = func(v reflect.Value) bool {
		if !v.IsValid() {
			return false
		}
		if v.Type() == vt {
			value := v.Interface().(model.Value)
			if value.Kind != model.ReferenceValue {
				for _, secret := range secrets {
					if reflect.DeepEqual(value, secret) {
						return true
					}
				}
			}
			return false
		}
		switch v.Kind() {
		case reflect.Pointer:
			if !v.IsNil() {
				return scan(v.Elem())
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if scan(v.Field(i)) {
					return true
				}
			}
		case reflect.Map:
			it := v.MapRange()
			for it.Next() {
				if scan(it.Value()) {
					return true
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				if scan(v.Index(i)) {
					return true
				}
			}
		}
		return false
	}
	if scan(reflect.ValueOf(out.Base)) || scan(reflect.ValueOf(out.Effects)) || scan(reflect.ValueOf(out.Contracts)) {
		return out, errors.New("legacy literal secret in protected plan requires an explicit safe revision before external planning")
	}
	body, err = json.Marshal(out)
	if err != nil || len(body) > 256*1024 {
		return out, errors.New("redacted planner context byte bound exceeded")
	}
	// Refs are read-only evidence IDs, never executable paths or URLs.
	for _, ref := range out.EvidenceRefs {
		if ref == "" || len(ref) > 256 || strings.ContainsAny(ref, "\r\n") {
			return out, errors.New("bounded read-only evidence reference required")
		}
	}
	return out, nil
}
