package durable

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data/beginattempt"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/viant/mechanize/data/loadrun"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func retryAdmissionFixture() (*loadrun.Run, integration.ExecutionMetadata, model.Step, string) {
	meta := integration.ExecutionMetadata{RunID: "run", PlanID: "plan", SessionID: "owned", OperationID: "resume-op", Resumed: true}
	step := model.Step{ID: "step", Effect: model.Effect{Class: model.ExternalNonIdempotent}}
	businessKey := `{"entity":{"kind":"string","string":"case-1"}}`
	attemptID := key("attempt", meta.RunID, meta.PlanID, step.ID)
	evidence, _ := json.Marshal(integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"})
	run := &loadrun.Run{Status: pointer("running"), EndlySessionId: pointer(meta.SessionID), EndlyOperationId: pointer(meta.OperationID), Attempts: []*loadrun.Attempt{{Id: pointer(attemptID), PlanId: pointer(meta.PlanID), StepId: pointer(step.ID)}}, Effects: []*loadrun.Effect{{Id: pointer(key("effect", attemptID)), AttemptId: pointer(attemptID), State: pointer("absent"), BusinessKey: pointer(businessKey), EvidenceJson: pointer(string(evidence))}}}
	return run, meta, step, businessKey
}

func TestAbsentRetryAdmissionRequiresCommittedOperationAndProvenIdentity(t *testing.T) {
	run, meta, step, businessKey := retryAdmissionFixture()
	attempt, prior, err := admitStepAttempt(run, meta, step, businessKey)
	if err != nil || prior != nil || attempt != key("attempt-resume", meta.RunID, meta.PlanID, step.ID, meta.OperationID) || attempt == *run.Attempts[0].Id {
		t.Fatalf("new append-only retry admission: %s %+v %v", attempt, prior, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*loadrun.Run, *integration.ExecutionMetadata)
	}{
		{"ordinary call", func(_ *loadrun.Run, m *integration.ExecutionMetadata) { m.Resumed = false }},
		{"stale correlation", func(r *loadrun.Run, _ *integration.ExecutionMetadata) { r.EndlyOperationId = pointer("other-op") }},
		{"forged session", func(_ *loadrun.Run, m *integration.ExecutionMetadata) { m.SessionID = "other-session" }},
		{"empty operation", func(_ *loadrun.Run, m *integration.ExecutionMetadata) { m.OperationID = "" }},
		{"stopped durable run", func(r *loadrun.Run, _ *integration.ExecutionMetadata) { r.Status = pointer("paused") }},
		{"changed entity", func(r *loadrun.Run, _ *integration.ExecutionMetadata) {
			r.Effects[0].BusinessKey = pointer("other-entity")
		}},
		{"unproven absence", func(r *loadrun.Run, _ *integration.ExecutionMetadata) {
			r.Effects[0].EvidenceJson = pointer(`{"dispatchState":"unknown"}`)
		}},
		{"unknown outcome", func(r *loadrun.Run, _ *integration.ExecutionMetadata) { r.Effects[0].State = pointer("unknown") }},
		{"uncommitted intent", func(r *loadrun.Run, _ *integration.ExecutionMetadata) { r.Effects[0].State = pointer("intent") }},
		{"broken attempt relation", func(r *loadrun.Run, _ *integration.ExecutionMetadata) { r.Effects[0].AttemptId = pointer("missing") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, m, s, k := retryAdmissionFixture()
			test.mutate(r, &m)
			if _, _, err := admitStepAttempt(r, m, s, k); !errors.Is(err, ErrNeedsReconciliation) {
				t.Fatalf("unsafe retry admitted: %v", err)
			}
		})
	}
}

func TestAbsentRetryRepeatsAdoptConfirmationOrStop(t *testing.T) {
	run, meta, step, businessKey := retryAdmissionFixture()
	retryID := key("attempt-resume", meta.RunID, meta.PlanID, step.ID, meta.OperationID)
	run.Attempts = append(run.Attempts, &loadrun.Attempt{Id: pointer(retryID), PlanId: pointer(meta.PlanID), StepId: pointer(step.ID)})
	confirmed, _ := json.Marshal(integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"})
	run.Effects = append(run.Effects, &loadrun.Effect{Id: pointer(key("effect", retryID)), AttemptId: pointer(retryID), State: pointer("confirmed"), BusinessKey: pointer(businessKey), EvidenceJson: pointer(string(confirmed))})
	if _, prior, err := admitStepAttempt(run, meta, step, businessKey); err != nil || prior == nil || prior.VerificationState != "verified" {
		t.Fatalf("confirmed retry not adopted: %+v %v", prior, err)
	}
	// Even a prior confirmed result cannot bypass uncertainty elsewhere in the run.
	otherAttempt := &loadrun.Attempt{Id: pointer("other"), PlanId: pointer(meta.PlanID), StepId: pointer("other-step")}
	run.Attempts = append(run.Attempts, otherAttempt)
	run.Effects = append(run.Effects, &loadrun.Effect{Id: pointer(key("effect", "other")), AttemptId: pointer("other"), State: pointer("unknown")})
	if _, _, err := admitStepAttempt(run, meta, step, businessKey); !errors.Is(err, ErrNeedsReconciliation) {
		t.Fatal("confirmed adoption bypassed global unknown barrier")
	}
	run.Effects = run.Effects[:2]
	run.Attempts = run.Attempts[:2]
	absence, _ := json.Marshal(integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"})
	run.Effects[1].State = pointer("absent")
	run.Effects[1].EvidenceJson = pointer(string(absence))
	if _, _, err := admitStepAttempt(run, meta, step, businessKey); !errors.Is(err, ErrNeedsReconciliation) {
		t.Fatal("one resumed operation allocated another attempt after absence")
	}
}

func TestGeneratedBeginAttemptRejectsForeignGraphAndPreservesState(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	owner, _ := auth.NewPrincipal("fixture:issuer", "", "begin-owner", nil)
	foreign, _ := auth.NewPrincipal("fixture:issuer", "", "begin-foreign", nil)
	ctx := auth.WithPrincipal(context.Background(), owner)
	b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		t.Fatal("foreign graph reached input dispatch")
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"entity": {Kind: model.StringValue, String: "case-1"}}
	planID, err := b.PreparePlan(ctx, owner, "owned-run", "owned-session", *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, user, err := b.bound(ctx, owner, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, foreignRoot := range []bool{false, true} {
		a := &beginattempt.Attempt{}
		a.SetNamespace(pointer(foreign.Namespace))
		a.SetId(pointer("foreign-attempt"))
		a.SetRunId(pointer("owned-run"))
		a.SetPlanId(pointer(planID))
		a.SetStepId(pointer(plan.Steps[0].ID))
		a.SetLeaseEpoch(pointer(1))
		a.SetState(pointer("intent"))
		a.SetCreatedAt(pointer(now()))
		intent := &beginattempt.Intent{}
		intent.SetNamespace(pointer(foreign.Namespace))
		intent.SetId(pointer("foreign-effect"))
		intent.SetAttemptId(pointer("foreign-attempt"))
		intent.SetRunId(pointer("owned-run"))
		intent.SetBusinessKey(pointer(`{"entity":{"kind":"string","string":"case-1"}}`))
		intent.SetState(pointer("intent"))
		intent.SetRevision(pointer(1))
		a.SetIntents([]*beginattempt.Intent{intent})
		event := &beginattempt.Event{}
		event.SetNamespace(pointer(foreign.Namespace))
		event.SetId(pointer("foreign-event"))
		event.SetRunId(pointer("owned-run"))
		event.SetAttemptId(pointer("foreign-attempt"))
		event.SetSequence(pointer(1))
		event.SetKind(pointer("intent"))
		event.SetPayloadJson(pointer("{}"))
		event.SetCreatedAt(pointer(now()))
		a.SetEvents([]*beginattempt.Event{event})
		run := &beginattempt.Run{}
		run.SetNamespace(pointer(owner.Namespace))
		if foreignRoot {
			run.SetNamespace(pointer(foreign.Namespace))
		}
		run.SetId(pointer("owned-run"))
		run.SetRevision(pointer(1))
		run.SetAttempts([]*beginattempt.Attempt{a})
		input := &beginattempt.BeginAttemptInput{}
		input.SetNamespace(owner.Namespace)
		input.SetBeginAttempt([]*beginattempt.Run{run})
		if _, err = invoke(bound, user.server, "beginattempt", "BeginAttempt", "PATCH", input, true); err == nil {
			t.Fatal("foreign graph admitted intent")
		}
	}
	state, err := b.StateGet(ctx, owner, "owned-run")
	if err != nil || state.Revision != 1 || len(state.UnresolvedEffects) != 0 {
		t.Fatalf("foreign graph changed state: %+v %v", state, err)
	}
	persisted, err := load(bound, user.server, owner, "owned-run")
	if err != nil || len(persisted.Attempts) != 0 || len(persisted.Effects) != 0 {
		t.Fatalf("foreign graph persisted child rows: %+v %v", persisted, err)
	}
	// Truly omitted declared parent links remain supported: native producers
	// supply the authoritative owner/run/attempt scope after ingress validation.
	a := &beginattempt.Attempt{}
	a.SetId(pointer("omitted-attempt"))
	a.SetPlanId(pointer(planID))
	a.SetStepId(pointer(plan.Steps[0].ID))
	a.SetLeaseEpoch(pointer(1))
	a.SetState(pointer("intent"))
	a.SetCreatedAt(pointer(now()))
	intent := &beginattempt.Intent{}
	intent.SetId(pointer("omitted-effect"))
	intent.SetRunId(pointer("owned-run"))
	intent.SetBusinessKey(pointer(`{"entity":{"kind":"string","string":"case-1"}}`))
	intent.SetState(pointer("intent"))
	intent.SetRevision(pointer(1))
	a.SetIntents([]*beginattempt.Intent{intent})
	event := &beginattempt.Event{}
	event.SetId(pointer("omitted-event"))
	event.SetRunId(pointer("owned-run"))
	event.SetSequence(pointer(1))
	event.SetKind(pointer("intent"))
	event.SetPayloadJson(pointer("{}"))
	event.SetCreatedAt(pointer(now()))
	a.SetEvents([]*beginattempt.Event{event})
	run := &beginattempt.Run{}
	run.SetNamespace(pointer(owner.Namespace))
	run.SetId(pointer("owned-run"))
	run.SetRevision(pointer(1))
	run.SetAttempts([]*beginattempt.Attempt{a})
	input := &beginattempt.BeginAttemptInput{}
	input.SetNamespace(owner.Namespace)
	input.SetBeginAttempt([]*beginattempt.Run{run})
	if _, err = invoke(bound, user.server, "beginattempt", "BeginAttempt", "PATCH", input, true); err != nil {
		t.Fatalf("safe native copied scope rejected: %v", err)
	}
	persisted, err = load(bound, user.server, owner, "owned-run")
	if err != nil || len(persisted.Attempts) != 1 || len(persisted.Effects) != 1 || *persisted.Attempts[0].Namespace != owner.Namespace || *persisted.Attempts[0].RunId != "owned-run" || *persisted.Effects[0].Namespace != owner.Namespace || *persisted.Effects[0].AttemptId != "omitted-attempt" {
		t.Fatalf("native producer scope not preserved: %+v %v", persisted, err)
	}

}
