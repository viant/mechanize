package durable

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/data/loadrun"
	repairs "github.com/viant/mechanize/engine/recovery"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	core "github.com/viant/mechanize/recovery"
	"github.com/viant/mechanize/script"
)

func stateBindingFixture(t *testing.T) (*model.Plan, *loadrun.Run) {
	t.Helper()
	plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	literal := model.Value{Kind: model.StringValue, String: "case-1"}
	alias := model.Value{Kind: model.ReferenceValue, Ref: "binding.entity"}
	chain := model.Value{Kind: model.ReferenceValue, Ref: "binding.alias"}
	free := model.Value{Kind: model.StringValue, String: "binding.entity"}
	plan.Bindings = []model.Binding{{Name: "entity", Type: "value", Value: &literal}, {Name: "alias", Type: "value", Value: &alias}, {Name: "chain", Type: "value", Value: &chain}, {Name: "free", Type: "value", Value: &free}}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"entity": {Kind: model.ReferenceValue, Ref: "binding.chain"}}
	if err = plan.Validate(); err != nil {
		t.Fatal(err)
	}
	run := stateBindingRun(t, *plan)
	run.Attempts = []*loadrun.Attempt{{Namespace: pointer("fixture"), RunId: pointer("run"), Id: pointer("attempt"), StepId: pointer(plan.Steps[0].ID), PlanId: pointer("plan")}}
	run.Effects = []*loadrun.Effect{{Namespace: pointer("fixture"), RunId: pointer("run"), Id: pointer("effect"), EvidenceJson: pointer(`{"dispatchState":"dispatched","verificationState":"verified"}`), AttemptId: pointer("attempt"), State: pointer("confirmed"), BusinessKey: pointer(`{"entity":{"kind":"string","string":"case-1"}}`)}}
	return plan, run
}
func stateBindingRun(t *testing.T, plan model.Plan) *loadrun.Run {
	t.Helper()
	body, err := json.Marshal(struct {
		Plan model.Plan `json:"plan"`
	}{plan})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	return &loadrun.Run{Namespace: pointer("fixture"), Id: pointer("run"), PlanId: pointer("plan"), Plan: &loadrun.PlanRevision{Namespace: pointer("fixture"), Id: pointer("plan"), ContentJson: pointer(string(body)), ContentHash: pointer(hex.EncodeToString(hash[:]))}}
}

func TestStateBindingTransitiveFreeze(t *testing.T) {
	_, run := stateBindingFixture(t)
	live := map[string]model.Value{"alias": {Kind: model.StringValue, String: "case-1"}}
	for _, name := range []string{"entity", "alias", "chain"} {
		if err := validateStateVariableSnapshot(run, live, map[string]model.Value{name: {Kind: model.StringValue, String: "case-2"}}); err == nil {
			t.Fatalf("confirmed alias dependency %s changed", name)
		}
	}
	if err := validateStateVariableSnapshot(run, live, map[string]model.Value{"free": {Kind: model.StringValue, String: "updated"}}); err != nil {
		t.Fatalf("literal mistaken for binding reference: %v", err)
	}
	if err := validateStateVariableSnapshot(run, live, map[string]model.Value{"undeclared": {Kind: model.StringValue, String: "value"}}); err == nil {
		t.Fatal("undeclared binding accepted")
	}
	if err := validateStateVariableSnapshot(run, live, map[string]model.Value{"free": {Kind: model.ReferenceValue, Ref: "binding.missing"}}); err == nil {
		t.Fatal("unknown patch alias accepted")
	}
	if err := validateStateVariableSnapshot(run, live, map[string]model.Value{"free": {Kind: model.ReferenceValue, Ref: "binding.free"}}); err == nil {
		t.Fatal("cyclic patch alias accepted")
	}
	if err := validateStateVariableSnapshot(run, map[string]model.Value{"undeclared": {Kind: model.StringValue, String: "value"}}, map[string]model.Value{"free": {Kind: model.StringValue, String: "value"}}); err == nil {
		t.Fatal("unknown persisted binding accepted")
	}
}

func TestStateBindingDerivedOutputFreeze(t *testing.T) {
	plan, err := script.Compile("let derived = app(\"com.example.Fixture\").getById(\"source\").read(\"value\")\napp(\"com.example.Fixture\").getById(\"save\").click()")
	if err != nil {
		t.Fatal(err)
	}
	entity := model.Value{Kind: model.StringValue, String: "case-1"}
	plan.Bindings = append(plan.Bindings, model.Binding{Name: "entity", Type: "value", Value: &entity})
	plan.Steps[0].Target.Locator.Value = model.Value{Kind: model.ReferenceValue, Ref: "binding.entity"}
	plan.Steps[1].Effect.BusinessKey = map[string]model.Value{"entity": {Kind: model.ReferenceValue, Ref: "binding.derived"}}
	if err = plan.Validate(); err != nil {
		t.Fatal(err)
	}
	run := stateBindingRun(t, *plan)
	run.Attempts = []*loadrun.Attempt{{Namespace: pointer("fixture"), RunId: pointer("run"), Id: pointer("attempt"), StepId: pointer(plan.Steps[1].ID), PlanId: pointer("plan")}}
	run.Effects = []*loadrun.Effect{{Namespace: pointer("fixture"), RunId: pointer("run"), Id: pointer("effect"), AttemptId: pointer("attempt"), State: pointer("confirmed"), BusinessKey: pointer(`{"entity":{"kind":"string","string":"case-1"}}`), EvidenceJson: pointer(`{"dispatchState":"dispatched","verificationState":"verified"}`)}}
	if err = validateStateVariableSnapshot(run, map[string]model.Value{"derived": entity}, map[string]model.Value{"entity": {Kind: model.StringValue, String: "case-2"}}); err == nil {
		t.Fatal("derived output provenance source changed")
	}
}

func TestResumeConfirmedBusinessKeyValidation(t *testing.T) {
	plan, run := stateBindingFixture(t)
	completed := map[string]integration.StepResult{plan.Steps[0].ID: {VerificationState: "verified"}}
	attempts := map[string]string{"attempt": plan.Steps[0].ID}
	if err := validateResumeBusinessKeys(*plan, nil, nil, completed, run.Effects, attempts); err != nil {
		t.Fatalf("original identity rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		live   map[string]model.Value
		mutate func(*model.Plan)
	}{
		{"changed entity", map[string]model.Value{"entity": {Kind: model.StringValue, String: "case-2"}}, nil},
		{"unknown alias", map[string]model.Value{"alias": {Kind: model.ReferenceValue, Ref: "binding.missing"}}, nil},
		{"sensitive alias", map[string]model.Value{"alias": {Kind: model.ReferenceValue, Ref: "input.secret"}}, func(p *model.Plan) {
			p.Inputs = map[string]model.InputDefinition{"secret": {Type: model.StringValue, Sensitive: true}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := *plan
			if test.mutate != nil {
				test.mutate(&candidate)
			}
			if err := validateResumeBusinessKeys(candidate, map[string]model.Value{"secret": {Kind: model.StringValue, String: "case-1"}}, test.live, completed, run.Effects, attempts); !errors.Is(err, ErrNeedsReconciliation) {
				t.Fatalf("identity drift admitted: %v", err)
			}
		})
	}
	run.Effects[0].BusinessKey = pointer(`{"entity":{"kind":"string","string":"other"}}`)
	if err := validateResumeBusinessKeys(*plan, nil, nil, completed, run.Effects, attempts); !errors.Is(err, ErrNeedsReconciliation) {
		t.Fatalf("stored entity mismatch admitted: %v", err)
	}
}

func TestResumeKnownAbsentRequiresExactEntityAndNonDispatchEvidence(t *testing.T) {
	plan, run := stateBindingFixture(t)
	attempts := map[string]string{"attempt": plan.Steps[0].ID}
	proof, _ := json.Marshal(integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"})
	run.Effects[0].State = pointer("absent")
	run.Effects[0].EvidenceJson = pointer(string(proof))
	if err := validateResumeBusinessKeys(*plan, nil, nil, nil, run.Effects, attempts); err != nil {
		t.Fatalf("proven absence rejected: %v", err)
	}
	if err := validateResumeBusinessKeys(*plan, nil, map[string]model.Value{"entity": {Kind: model.StringValue, String: "other"}}, nil, run.Effects, attempts); !errors.Is(err, ErrNeedsReconciliation) {
		t.Fatal("absent intent entity changed")
	}
	if err := validateResumeBusinessKeys(*plan, nil, nil, map[string]integration.StepResult{plan.Steps[0].ID: {VerificationState: "verified"}}, run.Effects, attempts); !errors.Is(err, ErrNeedsReconciliation) {
		t.Fatal("absence marked completed")
	}
	for _, state := range []string{"intent", "unknown"} {
		run.Effects[0].State = pointer(state)
		if err := validateResumeBusinessKeys(*plan, nil, nil, nil, run.Effects, attempts); !errors.Is(err, ErrNeedsReconciliation) {
			t.Fatalf("%s barrier removed", state)
		}
	}
	run.Effects[0].State = pointer("absent")
	for _, evidence := range []*string{nil, pointer("invalid JSON"), pointer(`{"dispatchState":"unknown"}`), pointer(`{"dispatchState":"dispatched","verificationState":"verified"}`)} {
		run.Effects[0].EvidenceJson = evidence
		if err := validateResumeBusinessKeys(*plan, nil, nil, nil, run.Effects, attempts); !errors.Is(err, ErrNeedsReconciliation) {
			t.Fatal("absence without explicit non-dispatch proof admitted")
		}
	}
}

func TestStateKnownAbsenceAllowsOnlyUnconsumedBindings(t *testing.T) {
	plan, run := stateBindingFixture(t)
	proof, _ := json.Marshal(integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"})
	run.Attempts = append(run.Attempts, &loadrun.Attempt{Namespace: run.Namespace, RunId: run.Id, Id: pointer("old-absent"), PlanId: run.PlanId, StepId: pointer(plan.Steps[0].ID)})
	run.Effects = append(run.Effects, &loadrun.Effect{Namespace: run.Namespace, RunId: run.Id, Id: pointer("old-absent-effect"), AttemptId: pointer("old-absent"), State: pointer("absent"), BusinessKey: run.Effects[0].BusinessKey, EvidenceJson: pointer(string(proof))})
	if err := validateStateVariableSnapshot(run, nil, map[string]model.Value{"free": {Kind: model.StringValue, String: "updated"}}); err != nil {
		t.Fatalf("known absent history blocked unrelated state: %v", err)
	}
	for _, name := range []string{"entity", "alias", "chain"} {
		if err := validateStateVariableSnapshot(run, nil, map[string]model.Value{name: {Kind: model.StringValue, String: "case-2"}}); err == nil {
			t.Fatalf("confirmed dependency %s changed", name)
		}
	}
	run.Effects = run.Effects[1:]
	run.Attempts = run.Attempts[1:]
	if err := validateStateVariableSnapshot(run, nil, map[string]model.Value{"free": {Kind: model.StringValue, String: "updated"}}); err != nil {
		t.Fatal("absence was treated as completed or unknown")
	}
	if err := validateStateVariableSnapshot(run, nil, map[string]model.Value{"entity": {Kind: model.StringValue, String: "case-2"}}); !errors.Is(err, ErrNeedsReconciliation) {
		t.Fatal("absence original entity changed")
	}
	for _, test := range []struct {
		name   string
		mutate func(*loadrun.Run)
	}{
		{"unknown", func(r *loadrun.Run) { r.Effects[0].State = pointer("unknown") }},
		{"intent", func(r *loadrun.Run) { r.Effects[0].State = pointer("intent") }},
		{"bad absence", func(r *loadrun.Run) { r.Effects[0].EvidenceJson = pointer(`{"dispatchState":"unknown"}`) }},
		{"foreign effect", func(r *loadrun.Run) { r.Effects[0].Namespace = pointer("foreign") }},
		{"foreign attempt", func(r *loadrun.Run) { r.Attempts[0].RunId = pointer("foreign-run") }},
		{"nil effect", func(r *loadrun.Run) { r.Effects[0] = nil }},
		{"nil attempt", func(r *loadrun.Run) { r.Attempts[0] = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, r := stateBindingFixture(t)
			r.Effects[0].State = pointer("absent")
			r.Effects[0].EvidenceJson = pointer(string(proof))
			test.mutate(r)
			if err := validateStateVariableSnapshot(r, nil, map[string]model.Value{"free": {Kind: model.StringValue, String: "updated"}}); err == nil {
				t.Fatal("unknown, malformed or foreign history allowed patch")
			}
		})
	}
}

func TestVerifiedRepairSnapshotFreezesInheritedDependencies(t *testing.T) {
	plan, _ := stateBindingFixture(t)
	snapshot := repairs.Snapshot{Plan: *plan, Repair: &repairs.RepairReference{}, Completed: map[string]integration.StepResult{plan.Steps[0].ID: {VerificationState: "verified"}}, Values: map[string]model.Value{"binding.alias": {Kind: model.StringValue, String: "case-1"}}, Effects: []core.EffectRecord{{StepID: plan.Steps[0].ID, State: "committed", BusinessKey: plan.Steps[0].Effect.BusinessKey}}}
	for _, binding := range plan.Bindings {
		if binding.Value != nil && binding.Name != "alias" {
			snapshot.Values["binding."+binding.Name] = *binding.Value
		}
	}
	if err := validateRepairedStateVariables(snapshot, map[string]model.Value{"free": {Kind: model.StringValue, String: "updated"}}); err != nil {
		t.Fatalf("verified inherited history blocked unrelated binding: %v", err)
	}
	for _, name := range []string{"entity", "alias", "chain"} {
		if err := validateRepairedStateVariables(snapshot, map[string]model.Value{name: {Kind: model.StringValue, String: "case-2"}}); err == nil {
			t.Fatalf("inherited dependency %s changed", name)
		}
	}
	snapshot.Unknown = true
	if err := validateRepairedStateVariables(snapshot, map[string]model.Value{"free": {Kind: model.StringValue, String: "updated"}}); !errors.Is(err, ErrNeedsReconciliation) {
		t.Fatal("unknown repair history allowed patch")
	}
}
