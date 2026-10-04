// Package recovery admits bounded immutable repairs. Endly remains the executor.
package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data/recoveryload"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	core "github.com/viant/mechanize/recovery"
	"github.com/viant/xdatly/handler"
)

type RunReference struct {
	RunID         string `json:"runId"`
	PlanID        string `json:"planId"`
	ObjectiveID   string `json:"objectiveId"`
	Revision      int    `json:"revision"`
	ContentHash   string `json:"contentHash"`
	PlanHash      string `json:"planHash"`
	ObjectiveHash string `json:"objectiveHash"`
	Status        string `json:"status"`
}
type Lineage struct {
	StepID         string `json:"stepId"`
	StepIndex      int    `json:"stepIndex"`
	OriginalPlanID string `json:"originalPlanId"`
	OriginalStepID string `json:"originalStepId"`
	AttemptID      string `json:"attemptId"`
	EffectID       string `json:"effectId"`
	BusinessKey    string `json:"businessKey"`
	ResultHash     string `json:"resultHash"`
	State          string `json:"state"`
}
type RepairReference struct {
	ID                string `json:"id"`
	RunID             string `json:"runId"`
	NewPlanID         string `json:"newPlanId"`
	ParentPlanID      string `json:"parentPlanId"`
	ParentContentHash string `json:"parentContentHash"`
	ParentHash        string `json:"parentHash"`
	PlanHash          string `json:"planHash"`
	ObjectiveHash     string `json:"objectiveHash"`
	PatchHash         string `json:"patchHash"`
	Revision          int    `json:"revision"`
	CompletedSteps    int    `json:"completedSteps"`
	IncidentID        string `json:"incidentId"`
}

// Snapshot is a private host/runtime DTO, not a planner/transport payload.
// Original ledger rows keep their original plan/attempt identity.
type Snapshot struct {
	Reference      RunReference
	Repair         *RepairReference
	Lineage        []Lineage
	Plan           model.Plan
	Inputs         map[string]model.Value
	Values         map[string]model.Value
	Completed      map[string]integration.StepResult
	CompletedSteps int
	Unknown        bool
	IncidentID     string
	Raw            *recoveryload.RecoveryRun
	Effects        []core.EffectRecord
}
type Evidence struct {
	Verified     bool
	Redacted     bool
	Observation  model.Observation
	EvidenceRefs []string
	Contracts    []core.Contract
	PolicyHash   string
	ValidUntil   time.Time
}
type Options struct {
	Invoke       func(context.Context, auth.Principal, exec.ComponentRequest) (any, error)
	Authorize    func(context.Context, auth.Principal, model.Surface) error
	Guard        func(context.Context, auth.Principal, RunReference) (func() error, error)
	RuntimeReady func(context.Context, auth.Principal) error
	// PrepareAdmission materializes the fixed writer under the stopped guard,
	// before collection of short-lived evidence and its admission permit.
	PrepareAdmission     func(context.Context, auth.Principal) error
	PrepareEvidence      func(context.Context, auth.Principal, Snapshot) (Evidence, error)
	VerifyEvidence       func(context.Context, auth.Principal, Snapshot, Evidence) error
	IncidentMaxRepairs   int
	IncidentMaxElapsedMs int64
}
type Service struct{ options Options }

func New(options Options) (*Service, error) {
	if options.Invoke == nil || options.Authorize == nil {
		return nil, errors.New("private Datly invocation and verified enrollment/surface authorization required")
	}
	if options.IncidentMaxRepairs == 0 {
		options.IncidentMaxRepairs = 1
	}
	if options.IncidentMaxElapsedMs == 0 {
		options.IncidentMaxElapsedMs = 30000
	}
	if options.IncidentMaxRepairs < 1 || options.IncidentMaxRepairs > 10 || options.IncidentMaxElapsedMs < 1 || options.IncidentMaxElapsedMs > 3600000 {
		return nil, errors.New("finite trusted incident budget required")
	}
	return &Service{options: options}, nil
}
func (s *Service) bound(ctx context.Context, requested auth.Principal) (auth.Principal, error) {
	p, err := auth.FromContext(ctx)
	if err != nil || requested.Validate() != nil || p.Namespace != requested.Namespace {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	if !p.HasScope("desktop:observe") && !p.HasScope("desktop:control") {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	if err = s.options.Authorize(ctx, p, model.Surface{}); err != nil {
		return auth.Principal{}, err
	}
	return p, ctx.Err()
}
func (s *Service) invoke(ctx context.Context, p auth.Principal, pkg, name, method string, input any, commit bool) (any, error) {
	var outcome handler.Outcome
	result, err := s.options.Invoke(ctx, p, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: input, Completion: func(o handler.Outcome) { outcome = o }})
	if err != nil {
		return nil, err
	}
	if commit && !outcome.CommitConfirmed() {
		return nil, errors.New("Datly repair admission commit is not confirmed")
	}
	return result, nil
}
func (s *Service) Snapshot(ctx context.Context, requested auth.Principal, runID string) (Snapshot, error) {
	p, err := s.bound(ctx, requested)
	if err != nil {
		return Snapshot{}, err
	}
	if runID == "" || len(runID) > 256 {
		return Snapshot{}, errors.New("bounded owned run identity required")
	}
	input := &recoveryload.LoadRecoveryInput{}
	input.SetNamespace(p.Namespace)
	input.SetRunID(runID)
	value, err := s.invoke(ctx, p, "recoveryload", "LoadRecovery", "GET", input, false)
	if err != nil {
		return Snapshot{}, err
	}
	output, ok := value.(*recoveryload.LoadRecoveryOutput)
	if !ok || output == nil || len(output.Data) != 1 {
		return Snapshot{}, errors.New("owned durable recovery run not found")
	}
	return s.decode(ctx, p, output.Data[0])
}

type planEnvelope struct {
	Plan   model.Plan             `json:"plan"`
	Inputs map[string]model.Value `json:"inputs"`
}

func digest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
func (s *Service) decode(ctx context.Context, p auth.Principal, row *recoveryload.RecoveryRun) (Snapshot, error) {
	out := Snapshot{Raw: row, Completed: map[string]integration.StepResult{}, Values: map[string]model.Value{}}
	if row == nil || row.Namespace == nil || *row.Namespace != p.Namespace || row.Id == nil || row.PlanId == nil || row.ObjectiveId == nil || row.Revision == nil || row.Status == nil {
		return out, auth.ErrUnauthorized
	}
	if len(row.Plans) > 1000 || len(row.Attempts) > 1000 || len(row.Effects) > 1000 || len(row.Milestones) > 1000 || len(row.Events) > 2000 || len(row.Lineage) > 10000 || len(row.Repairs) > 10 {
		return out, errors.New("durable recovery context bound exceeded")
	}
	plans := map[string]planEnvelope{}
	planRows := map[string]*recoveryload.PlanRevision{}
	for _, plan := range row.Plans {
		if plan == nil || plan.Namespace == nil || *plan.Namespace != p.Namespace || plan.Id == nil || plan.ObjectiveId == nil || *plan.ObjectiveId != *row.ObjectiveId || plan.ContentHash == nil || plan.ContentJson == nil || digest([]byte(*plan.ContentJson)) != *plan.ContentHash {
			return out, errors.New("immutable owned plan hash/identity mismatch")
		}
		var env planEnvelope
		if err := json.Unmarshal([]byte(*plan.ContentJson), &env); err != nil {
			return out, err
		}
		if err := env.Plan.Validate(); err != nil {
			return out, err
		}
		plans[*plan.Id] = env
		planRows[*plan.Id] = plan
	}
	current, ok := plans[*row.PlanId]
	if !ok {
		return out, errors.New("current immutable plan absent")
	}
	out.Plan = current.Plan
	out.Inputs = current.Inputs
	currentRow := planRows[*row.PlanId]
	out.Reference = RunReference{RunID: *row.Id, PlanID: *row.PlanId, ObjectiveID: *row.ObjectiveId, Revision: *row.Revision, Status: *row.Status, ContentHash: *currentRow.ContentHash, PlanHash: core.Hash(current.Plan), ObjectiveHash: core.ObjectiveHash(current.Plan)}
	for _, surface := range surfaces(out.Plan) {
		if err := s.options.Authorize(ctx, p, surface); err != nil {
			return out, err
		}
	}
	for name, value := range current.Inputs {
		out.Values["input."+name] = value
	}
	for _, binding := range current.Plan.Bindings {
		if binding.Value != nil {
			out.Values["binding."+binding.Name] = *binding.Value
		}
	}
	for _, variable := range row.Variables {
		if variable.Namespace == nil || *variable.Namespace != p.Namespace || variable.RunId == nil || *variable.RunId != *row.Id || variable.Name == nil || variable.ValueJson == nil {
			return out, auth.ErrUnauthorized
		}
		var value model.Value
		if err := json.Unmarshal([]byte(*variable.ValueJson), &value); err != nil {
			return out, err
		}
		if err := value.Validate(); err != nil {
			return out, err
		}
		out.Values["binding."+*variable.Name] = value
	}
	for _, repair := range row.Repairs {
		if repair.Namespace == nil || *repair.Namespace != p.Namespace || repair.RunId == nil || *repair.RunId != *row.Id {
			return out, auth.ErrUnauthorized
		}
		if repair.NewPlanId != nil && *repair.NewPlanId == *row.PlanId {
			ref, err := repairReference(repair)
			if err != nil {
				return out, err
			}
			if ref.PlanHash != out.Reference.PlanHash || ref.ObjectiveHash != out.Reference.ObjectiveHash {
				return out, errors.New("active repair hash mismatch")
			}
			out.Repair = &ref
		}
	}
	byAttempt := map[string]Lineage{}
	for _, entry := range row.Lineage {
		if entry.Namespace == nil || *entry.Namespace != p.Namespace || entry.RunId == nil || *entry.RunId != *row.Id {
			return out, auth.ErrUnauthorized
		}
		if entry.NewPlanId == nil || *entry.NewPlanId != *row.PlanId {
			continue
		}
		item, err := decodeLineage(entry)
		if err != nil {
			return out, err
		}
		if _, exists := byAttempt[item.AttemptID]; exists {
			return out, errors.New("duplicate repair attempt lineage")
		}
		byAttempt[item.AttemptID] = item
		out.Lineage = append(out.Lineage, item)
	}
	attempts := map[string]*recoveryload.Attempt{}
	for _, attempt := range row.Attempts {
		if attempt.Namespace == nil || *attempt.Namespace != p.Namespace || attempt.RunId == nil || *attempt.RunId != *row.Id || attempt.Id == nil || attempt.StepId == nil || attempt.PlanId == nil {
			return out, auth.ErrUnauthorized
		}
		if _, exists := attempts[*attempt.Id]; exists {
			return out, errors.New("duplicate durable attempt")
		}
		attempts[*attempt.Id] = attempt
	}
	stepIndex := map[string]int{}
	for i, step := range current.Plan.Steps {
		stepIndex[step.ID] = i
	}
	verifiedMilestones := map[string]bool{}
	for _, milestone := range row.Milestones {
		if milestone.Namespace == nil || *milestone.Namespace != p.Namespace || milestone.RunId == nil || *milestone.RunId != *row.Id || milestone.AttemptId == nil || milestone.State == nil || *milestone.State != "verified" {
			return out, errors.New("invalid verified milestone history")
		}
		verifiedMilestones[*milestone.AttemptId] = true
	}
	type known struct {
		effect     *recoveryload.Effect
		attempt    *recoveryload.Attempt
		result     integration.StepResult
		stepID     string
		sourceStep model.Step
	}
	records := []known{}
	effectsSeen := map[string]bool{}
	for _, effect := range row.Effects {
		if effect.Namespace == nil || *effect.Namespace != p.Namespace || effect.RunId == nil || *effect.RunId != *row.Id || effect.Id == nil || effect.AttemptId == nil || effect.State == nil || effect.BusinessKey == nil {
			return out, auth.ErrUnauthorized
		}
		if effectsSeen[*effect.AttemptId] {
			return out, errors.New("duplicate effect per original attempt")
		}
		effectsSeen[*effect.AttemptId] = true
		attempt := attempts[*effect.AttemptId]
		if attempt == nil {
			return out, errors.New("effect original attempt missing")
		}
		if *effect.State == "intent" || *effect.State == "unknown" {
			out.Unknown = true
			continue
		}
		if *effect.State != "confirmed" && *effect.State != "absent" || effect.EvidenceJson == nil {
			return out, errors.New("invalid durable effect proof")
		}
		var result integration.StepResult
		if err := json.Unmarshal([]byte(*effect.EvidenceJson), &result); err != nil {
			return out, err
		}
		if *effect.State == "confirmed" && (result.VerificationState != "verified" || !verifiedMilestones[*attempt.Id]) {
			return out, errors.New("confirmed effect lacks verified milestone proof")
		}
		if *effect.State == "absent" && result.DispatchState != "notDispatched" {
			out.Unknown = true
			continue
		}
		original, exists := plans[*attempt.PlanId]
		if !exists || core.ObjectiveHash(original.Plan) != out.Reference.ObjectiveHash || !reflect.DeepEqual(original.Inputs, current.Inputs) {
			return out, errors.New("original attempt objective/input lineage mismatch")
		}
		var originalStep *model.Step
		for i := range original.Plan.Steps {
			if original.Plan.Steps[i].ID == *attempt.StepId {
				originalStep = &original.Plan.Steps[i]
				break
			}
		}
		if originalStep == nil {
			return out, errors.New("original attempt step missing")
		}
		activeStepID := *attempt.StepId
		if *attempt.PlanId != *row.PlanId {
			entry, exists := byAttempt[*attempt.Id]
			if !exists || entry.OriginalPlanID != *attempt.PlanId || entry.OriginalStepID != *attempt.StepId || entry.EffectID != *effect.Id || entry.BusinessKey != *effect.BusinessKey || entry.ResultHash != digest([]byte(*effect.EvidenceJson)) || entry.State != *effect.State {
				return out, errors.New("original ledger is outside verified repair lineage")
			}
			activeStepID = entry.StepID
		}
		index, exists := stepIndex[activeStepID]
		if !exists {
			return out, errors.New("lineage step absent from active plan")
		}
		if entry, exists := byAttempt[*attempt.Id]; exists && entry.StepIndex != index {
			return out, errors.New("repair step index mismatch")
		}
		if *effect.State == "confirmed" && !reflect.DeepEqual(*originalStep, current.Plan.Steps[index]) {
			return out, errors.New("completed effect was modified by repair")
		}
		records = append(records, known{effect, attempt, result, activeStepID, *originalStep})
	}
	for id := range attempts {
		if !effectsSeen[id] {
			out.Unknown = true
		}
	}
	if out.Unknown {
		return out, nil
	}
	byStep := map[string][]known{}
	for _, record := range records {
		byStep[record.stepID] = append(byStep[record.stepID], record)
	}
	completedSeen := false
	for index, step := range current.Plan.Steps {
		committed := false
		for _, record := range byStep[step.ID] {
			key, err := canonicalKey(record.sourceStep.Effect.BusinessKey, out.Values)
			if err != nil || key != *record.effect.BusinessKey {
				return out, errors.New("exact original business key differs from immutable input/binding boundary")
			}
			state := "absent"
			if *record.effect.State == "confirmed" {
				state = "committed"
				if committed {
					return out, errors.New("multiple confirmed effects for same step")
				}
				committed = true
				out.Completed[step.ID] = record.result
			}
			out.Effects = append(out.Effects, core.EffectRecord{StepID: step.ID, BusinessKey: record.sourceStep.Effect.BusinessKey, State: state})
		}
		if committed {
			if completedSeen {
				return out, errors.New("confirmed milestones are not a contiguous prefix; readonly milestone reconstruction unavailable")
			}
			out.CompletedSteps = index + 1
			result := out.Completed[step.ID]
			if step.Bind != "" {
				if result.Value == nil {
					return out, errors.New("completed binding lacks durable proof")
				}
				out.Values["binding."+step.Bind] = *result.Value
			}
		} else {
			completedSeen = true
		}
	}
	incidentKey := "objective:" + out.Reference.ObjectiveHash
	for _, step := range current.Plan.Steps[out.CompletedSteps:] {
		if step.Effect.Class != model.ReadOnly {
			key, err := canonicalKey(step.Effect.BusinessKey, out.Values)
			if err != nil {
				return out, err
			}
			incidentKey = key
			break
		}
	}
	out.IncidentID = core.Hash([]string{out.Reference.RunID, out.Reference.ObjectiveHash, incidentKey})
	return out, nil
}
func decodeLineage(row *recoveryload.RepairLineage) (Lineage, error) {
	if row.StepId == nil || row.StepIndex == nil || row.OriginalPlanId == nil || row.OriginalStepId == nil || row.AttemptId == nil || row.EffectId == nil || row.BusinessKey == nil || row.ResultHash == nil || row.State == nil {
		return Lineage{}, errors.New("complete immutable repair lineage required")
	}
	return Lineage{*row.StepId, *row.StepIndex, *row.OriginalPlanId, *row.OriginalStepId, *row.AttemptId, *row.EffectId, *row.BusinessKey, *row.ResultHash, *row.State}, nil
}
func repairReference(row *recoveryload.RepairRevision) (RepairReference, error) {
	if row.Id == nil || row.RunId == nil || row.NewPlanId == nil || row.ParentPlanId == nil || row.ParentContentHash == nil || row.ParentPlanHash == nil || row.PlanHash == nil || row.ObjectiveHash == nil || row.PatchHash == nil || row.RunRevision == nil || row.CompletedSteps == nil || row.IncidentId == nil {
		return RepairReference{}, errors.New("complete immutable repair reference required")
	}
	return RepairReference{*row.Id, *row.RunId, *row.NewPlanId, *row.ParentPlanId, *row.ParentContentHash, *row.ParentPlanHash, *row.PlanHash, *row.ObjectiveHash, *row.PatchHash, *row.RunRevision, *row.CompletedSteps, *row.IncidentId}, nil
}
func canonicalKey(expressions map[string]model.Value, values map[string]model.Value) (string, error) {
	if len(expressions) == 0 {
		return "", errors.New("exact business key required")
	}
	resolved := map[string]model.Value{}
	for name, value := range expressions {
		actual, err := model.ResolveValue(value, values)
		if err != nil {
			return "", err
		}
		resolved[name] = actual
	}
	content, err := json.Marshal(resolved)
	return string(content), err
}
func surfaces(plan model.Plan) []model.Surface {
	seen := map[model.Surface]bool{}
	var visit func(reflect.Value)
	st := reflect.TypeOf(model.Surface{})
	visit = func(v reflect.Value) {
		if !v.IsValid() {
			return
		}
		if v.Type() == st {
			surface := v.Interface().(model.Surface)
			if surface.Kind != "" {
				seen[surface] = true
			}
			return
		}
		switch v.Kind() {
		case reflect.Pointer:
			if !v.IsNil() {
				visit(v.Elem())
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				visit(v.Field(i))
			}
		case reflect.Map:
			it := v.MapRange()
			for it.Next() {
				visit(it.Value())
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				visit(v.Index(i))
			}
		}
	}
	visit(reflect.ValueOf(plan))
	out := []model.Surface{}
	for surface := range seen {
		out = append(out, surface)
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]) < fmt.Sprint(out[j]) })
	return out
}
