// Package recovery validates bounded proposals. Endly executes and Datly persists
// the returned revision; this package has no tools, scheduler or database access.
package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type PlanPatch struct {
	BaseHash       string       `json:"baseHash"`
	ObjectiveHash  string       `json:"objectiveHash"`
	RemainingSteps []model.Step `json:"remainingSteps"`
	EvidenceRefs   []string     `json:"evidenceRefs"`
}
type Budget struct {
	MaxRepairs   int   `json:"maxRepairs"`
	UsedRepairs  int   `json:"usedRepairs"`
	MaxElapsedMs int64 `json:"maxElapsedMs"`
	ElapsedMs    int64 `json:"elapsedMs"`
}
type EffectRecord struct {
	StepID      string                 `json:"stepId"`
	BusinessKey map[string]model.Value `json:"businessKey"`
	State       string                 `json:"state"` // committed, absent, unknown; supplied by authoritative reconciliation
}

// Contract is trusted executor/adapter metadata, never a planner-supplied grant.
type Contract struct {
	Profile       string           `json:"profile"`
	Action        string           `json:"action"`
	Surface       model.Surface    `json:"surface"`
	Permissions   []string         `json:"permissions"`
	Qualified     bool             `json:"qualified"`
	Postcondition *model.Predicate `json:"postcondition,omitempty"`
	Reconcile     *model.Predicate `json:"reconcile,omitempty"`
	// TargetScope restricts a qualified route to leaf-locator repair. Every
	// other selector field, including ancestor locators, must remain exact.
	// Nil retains the contract's existing full-route qualification.
	TargetScope *model.Selector `json:"targetScope,omitempty"`
}
type RecoveryContext struct {
	Namespace      string                 `json:"namespace"`
	Base           model.Plan             `json:"base"`
	CompletedSteps int                    `json:"completedSteps"`
	ObjectiveHash  string                 `json:"objectiveHash"`
	Bindings       map[string]model.Value `json:"bindings"`
	Effects        []EffectRecord         `json:"effects"`
	Contracts      []Contract             `json:"contracts"`
	IncidentBudget Budget                 `json:"incidentBudget"`
	WorkflowBudget Budget                 `json:"workflowBudget"`
	// These are already redacted, read-only evidence, without handles or callbacks.
	Observation  model.Observation `json:"observation"`
	EvidenceRefs []string          `json:"evidenceRefs"`
	Now          time.Time         `json:"now"`
}
type Proposer interface {
	Propose(context.Context, RecoveryContext) (PlanPatch, error)
}
type Revision struct {
	Namespace     string     `json:"namespace"`
	ParentHash    string     `json:"parentHash"`
	Hash          string     `json:"hash"`
	ObjectiveHash string     `json:"objectiveHash"`
	Plan          model.Plan `json:"plan"`
	ResumeStep    int        `json:"resumeStep"`
	EvidenceRefs  []string   `json:"evidenceRefs"`
}

func Hash(v any) string {
	data, _ := json.Marshal(v)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ObjectiveHash protects every non-step field, including entity inputs, policy,
// constraints, dependencies and registered objective predicates.
func ObjectiveHash(p model.Plan) string { p.Steps = nil; return Hash(p) }
func attention(code, msg string) error {
	return &model.MechanizeError{Code: code, Message: msg, Stage: "recovery", EffectState: "needsAttention"}
}
func checkBudget(b Budget) bool {
	return b.MaxRepairs > 0 && b.MaxRepairs <= 10 && b.UsedRepairs >= 0 && b.UsedRepairs < b.MaxRepairs && b.MaxElapsedMs > 0 && b.MaxElapsedMs <= 3600000 && b.ElapsedMs >= 0 && b.ElapsedMs < b.MaxElapsedMs
}
func Validate(ctx context.Context, r RecoveryContext, patch PlanPatch) (Revision, error) {
	p, err := auth.FromContext(ctx)
	if err != nil {
		return Revision{}, err
	}
	fail := func(code, msg string) (Revision, error) { return Revision{}, attention(code, msg) }
	if r.Namespace != p.Namespace {
		return fail("scopeDenied", "recovery context must belong to the verified namespace")
	}
	if err = r.Base.Validate(); err != nil {
		return fail("invalidBase", "base plan is invalid: "+err.Error())
	}
	if r.Base.Objective == nil || r.Base.Constraints == nil || r.Base.Recovery == nil || r.Base.Recovery.OnUnknownEffect != "needsAttention" {
		return fail("unknownPolicy", "objective, constraints and an explicit needsAttention unknown-effect policy are required")
	}
	if r.CompletedSteps < 0 || r.CompletedSteps > len(r.Base.Steps) {
		return fail("invalidProgress", "completed prefix is invalid; reload committed milestones")
	}
	if patch.BaseHash != Hash(r.Base) {
		return fail("staleRevision", "base hash changed; reload the owned run revision")
	}
	objective := ObjectiveHash(r.Base)
	if r.ObjectiveHash != objective || patch.ObjectiveHash != objective {
		return fail("objectiveChanged", "objective hash differs; recovery cannot redefine objective or constraints")
	}
	if !checkBudget(r.IncidentBudget) || !checkBudget(r.WorkflowBudget) || r.WorkflowBudget.MaxRepairs > r.Base.Recovery.MaxRepairs || r.WorkflowBudget.MaxElapsedMs > r.Base.Recovery.MaxElapsedMs {
		return fail("budgetExhausted", "incident or workflow repair budget is invalid or exhausted; request attention")
	}
	if len(patch.RemainingSteps) == 0 || len(patch.RemainingSteps) > 1000 || len(patch.EvidenceRefs) == 0 {
		return fail("invalidPatch", "patch needs 1..1000 remaining steps and bounded evidence provenance")
	}
	if len(r.Effects) > 1000 || len(r.Contracts) > 1000 {
		return fail("contextTooLarge", "effect history and action contracts exceed bounded planner input")
	}
	evidence := map[string]bool{}
	for _, ref := range r.EvidenceRefs {
		evidence[ref] = true
	}
	for _, ref := range patch.EvidenceRefs {
		if !evidence[ref] || ref == "" {
			return fail("invalidEvidence", "patch evidence must reference the provided read-only evidence")
		}
	}
	for _, e := range r.Effects {
		switch e.State {
		case "unknown":
			return fail("unknownEffect", "reconcile unknown effect for step "+e.StepID+" authoritatively before any plan repair")
		case "committed", "absent":
		default:
			return fail("unknownEffect", "invalid effect history state; obtain authoritative reconciliation")
		}
	}
	var next model.Plan
	encoded, _ := json.Marshal(r.Base)
	_ = json.Unmarshal(encoded, &next)
	next.Steps = append(next.Steps[:r.CompletedSteps:r.CompletedSteps], patch.RemainingSteps...)
	if err = next.Validate(); err != nil {
		return fail("invalidPatch", "typed remaining plan is invalid: "+err.Error())
	}
	seenKeys := map[string]bool{}
	for _, e := range r.Effects {
		if e.State == "committed" {
			key, err := resolvedKey(e.BusinessKey, r.Bindings)
			if err != nil {
				return fail("invalidHistory", err.Error())
			}
			if len(e.BusinessKey) > 0 {
				seenKeys[key] = true
			}
		}
	}
	// Every remaining business effect retains its registered outcome contract.
	expected := map[string]model.Step{}
	for _, s := range r.Base.Steps[r.CompletedSteps:] {
		if s.Effect.Class == model.ReadOnly {
			continue
		}
		key, e := resolvedKey(s.Effect.BusinessKey, r.Bindings)
		if e != nil || len(s.Effect.BusinessKey) == 0 {
			return fail("invalidBase", "remaining effect needs a resolved business key")
		}
		if _, exists := expected[key]; exists {
			return fail("duplicateEffect", "base remaining route repeats a business effect")
		}
		expected[key] = s
	}
	total := int64(0)
	for _, s := range patch.RemainingSteps {
		total += s.TimeoutMs
		for _, predicate := range []*model.Predicate{s.Precondition, s.Postcondition, s.Effect.Reconcile} {
			if predicate != nil {
				total += predicate.TimeoutMs
			}
		}
		if total > r.IncidentBudget.MaxElapsedMs-r.IncidentBudget.ElapsedMs || total > r.WorkflowBudget.MaxElapsedMs-r.WorkflowBudget.ElapsedMs {
			return fail("budgetExhausted", "proposed route exceeds the remaining incident or workflow deadline")
		}
		for _, done := range r.Base.Steps[:r.CompletedSteps] {
			if done.ID == s.ID {
				return fail("committedStep", "patch cannot replace or replay committed step "+s.ID)
			}
		}
		if !allowedSurface(s.Target.Surface, *r.Base.Constraints) {
			return fail("scopeDenied", "step "+s.ID+" targets an app or origin outside objective constraints")
		}
		matches := []Contract{}
		for _, c := range r.Contracts {
			if c.Qualified && c.Profile == s.SemanticsProfile && c.Action == s.Action && c.Surface == s.Target.Surface {
				matches = append(matches, c)
			}
		}
		if len(matches) != 1 {
			return fail("unqualifiedRoute", "step "+s.ID+" requires exactly one qualified profile/action/surface contract")
		}
		c := matches[0]
		if c.TargetScope != nil && !locatorRepairWithinScope(*c.TargetScope, s.Target) {
			return fail("scopeDenied", "step "+s.ID+" may change only its enrolled exact semantic leaf locator")
		}
		for _, permission := range c.Permissions {
			if !p.HasScope(permission) {
				return fail("scopeDenied", "principal lacks permission "+permission)
			}
		}
		if _, err = s.ResolveArguments(r.Bindings); err != nil {
			return fail("invalidArguments", "step "+s.ID+": "+err.Error())
		}
		if s.Effect.Class != model.ReadOnly {
			if s.Target.Cardinality != "one" {
				return fail("ambiguousTarget", "repair mutations require a strict unique target")
			}
			if c.Postcondition == nil || !reflect.DeepEqual(c.Postcondition, s.Postcondition) || c.Reconcile == nil || !reflect.DeepEqual(c.Reconcile, s.Effect.Reconcile) {
				return fail("verificationChanged", "mutation must preserve the qualified postcondition and reconciliation predicates")
			}
			if len(s.Effect.BusinessKey) == 0 {
				return fail("missingBusinessKey", "mutation needs a resolved business key before repair")
			}
			key, err := resolvedKey(s.Effect.BusinessKey, r.Bindings)
			if err != nil {
				return fail("invalidBusinessKey", err.Error())
			}
			original, exists := expected[key]
			if !exists || !reflect.DeepEqual(original.Postcondition, s.Postcondition) || !reflect.DeepEqual(original.Effect, s.Effect) {
				return fail("effectChanged", "repair cannot introduce a new business effect or change its outcome contract")
			}
			delete(expected, key)
			if seenKeys[key] {
				return fail("duplicateEffect", "business effect is already committed or repeated in this patch; reconcile before replay")
			}
			seenKeys[key] = true
		}
	}
	if len(expected) > 0 {
		return fail("milestoneSkipped", "remaining business effects may not be removed without committed outcome evidence")
	}
	// Deep-copy the proposal as well: caller edits cannot mutate the new revision.
	encoded, _ = json.Marshal(next)
	_ = json.Unmarshal(encoded, &next)
	return Revision{Namespace: p.Namespace, ParentHash: patch.BaseHash, Hash: Hash(next), ObjectiveHash: objective, Plan: next, ResumeStep: r.CompletedSteps, EvidenceRefs: append([]string(nil), patch.EvidenceRefs...)}, nil
}

func locatorRepairWithinScope(enrolled, proposed model.Selector) bool {
	semantic := func(target model.Selector) bool {
		if target.Validate() != nil || target.Locator == nil || !target.Locator.Exact || target.Locator.Value.Kind != model.StringValue || target.Locator.Value.String == "" {
			return false
		}
		switch target.Locator.Strategy {
		case "id", "name", "role":
		default:
			return false
		}
		if name := target.Locator.Name; name != nil && (name.Kind != model.StringValue || name.String == "") {
			return false
		}
		return true
	}
	if !semantic(enrolled) || !semantic(proposed) {
		return false
	}
	// Clear only the leaf locator on value copies: the original selectors and
	// their nested ancestor chains remain immutable, and new selector fields
	// automatically participate in the scope comparison.
	enrolled.Locator, proposed.Locator = nil, nil
	return reflect.DeepEqual(enrolled, proposed)
}

func allowedSurface(s model.Surface, c model.Constraints) bool {
	allowed := c.AllowedApps
	key := s.BundleID
	if s.Kind == "web" {
		allowed = c.AllowedOrigins
		key = s.Origin
	}
	for _, v := range allowed {
		if v == key && key != "" {
			return true
		}
	}
	return false
}
func resolvedKey(k map[string]model.Value, bindings map[string]model.Value) (string, error) {
	out := map[string]model.Value{}
	for n, v := range k {
		x, err := model.ResolveValue(v, bindings)
		if err != nil {
			return "", fmt.Errorf("business key %s: %w", n, err)
		}
		out[n] = x
	}
	return Hash(out), nil
}

// Propose bounds and clones read-only input before crossing the optional planner
// boundary. The resulting proposal always passes the same validator.
func Propose(ctx context.Context, proposer Proposer, r RecoveryContext) (Revision, error) {
	if proposer == nil {
		return Revision{}, attention("plannerUnavailable", "no configured recovery proposer")
	}
	principal, err := auth.FromContext(ctx)
	if err != nil {
		return Revision{}, err
	}
	if r.Namespace != principal.Namespace {
		return Revision{}, attention("scopeDenied", "planner context is outside the verified namespace")
	}
	if r.Base.Objective == nil || r.Base.Constraints == nil || r.Base.Recovery == nil || r.Base.Recovery.OnUnknownEffect != "needsAttention" || r.ObjectiveHash != ObjectiveHash(r.Base) {
		return Revision{}, attention("invalidObjective", "planner requires an immutable objective and explicit safe recovery policy")
	}
	for _, e := range r.Effects {
		if e.State != "committed" && e.State != "absent" {
			return Revision{}, attention("unknownEffect", "reconcile uncertain effects before invoking a planner")
		}
	}
	if err := r.Base.Validate(); err != nil {
		return Revision{}, attention("invalidBase", err.Error())
	}
	if !checkBudget(r.IncidentBudget) || !checkBudget(r.WorkflowBudget) {
		return Revision{}, attention("budgetExhausted", "planner budget is exhausted")
	}
	data, err := json.Marshal(r)
	if err != nil || len(data) > 256*1024 || len(r.Observation.Nodes) > 256 || r.Observation.Truncated || r.Now.IsZero() || r.Observation.Ended.IsZero() || r.Observation.Ended.After(r.Now) || r.Now.Sub(r.Observation.Ended) > 5*time.Second {
		return Revision{}, attention("invalidObservation", "planner requires redacted complete fresh observation and context bounded to 256 KiB/256 nodes")
	}
	var copy RecoveryContext
	_ = json.Unmarshal(data, &copy)
	ms := r.IncidentBudget.MaxElapsedMs - r.IncidentBudget.ElapsedMs
	if other := r.WorkflowBudget.MaxElapsedMs - r.WorkflowBudget.ElapsedMs; other < ms {
		ms = other
	}
	bounded, cancel := context.WithTimeout(ctx, time.Duration(ms)*time.Millisecond)
	defer cancel()
	started := time.Now()
	patch, err := proposer.Propose(bounded, copy)
	if err != nil {
		return Revision{}, err
	}
	if err = bounded.Err(); err != nil {
		return Revision{}, err
	}
	elapsed := time.Since(started).Milliseconds()
	r.IncidentBudget.ElapsedMs += elapsed
	r.WorkflowBudget.ElapsedMs += elapsed
	return Validate(ctx, r, patch)
}

// DecodePatch rejects unknown fields, executable source and trailing JSON at the
// planner transport boundary; all contained DSL actions remain closed typed IR.
func DecodePatch(data []byte) (PlanPatch, error) {
	var patch PlanPatch
	if len(data) > 256*1024 {
		return patch, attention("patchTooLarge", "planner response exceeds 256 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&patch); err != nil {
		return PlanPatch{}, attention("invalidPatch", err.Error())
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return PlanPatch{}, attention("invalidPatch", "planner response must contain exactly one typed patch")
	}
	return patch, nil
}
