package reconcileeffect_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/viant/datly/bootstrap/connector"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/datly/standalone"
	"github.com/viant/datly/standalone/config"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/data/reconcileeffect"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/internal/datlytest"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/xdatly/handler"
)

func ptr[T any](v T) *T { return &v }

type fixture struct {
	ctx       context.Context
	server    *standalone.Server
	fixtures  *standalone.Server
	principal auth.Principal
}

func openFixture(t *testing.T) *fixture {
	t.Helper()
	p, err := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx, err = data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := data.Provision(ctx, t.TempDir(), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := datlytest.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	server, err := standalone.New(ctx, standalone.Options{Config: &config.Config{BaseDir: root, Connector: "user", Connectors: []connector.Config{cfg}, GoBootstrap: &config.Packages{Packages: []string{"github.com/viant/mechanize/data/reconcileeffect", "github.com/viant/mechanize/data/loadrun"}}}, Holders: []any{reconcileeffect.ReconcileEffectComponent{}, loadrun.LoadRunComponent{}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Reload(ctx, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()); _ = fixtures.Shutdown(context.Background()) })
	return &fixture{ctx: ctx, server: server, fixtures: fixtures, principal: p}
}
func (f *fixture) seed(t *testing.T, name string, resumedOperation ...string) (data.ReconcileEffectAuthority, context.Context) {
	t.Helper()
	ns := f.principal.Namespace
	runID := data.ReconcileEffectKey("fixture-run", name)
	step := model.Step{ID: "open-extensions", Action: "element.press", TimeoutMs: 1000, Target: model.Selector{Surface: model.Surface{Kind: "native", BundleID: "com.google.Chrome", ProcessID: 42, ProcessStartToken: "1790000000:1"}, Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "extensions"}, Exact: true}, Cardinality: "one"}, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"task": {Kind: model.StringValue, String: "extensions-view"}}}}
	plan := model.Plan{SchemaVersion: 1, Steps: []model.Step{step}}
	raw, err := json.Marshal(struct {
		Plan   model.Plan             `json:"plan"`
		Inputs map[string]model.Value `json:"inputs"`
	}{plan, map[string]model.Value{}})
	if err != nil {
		t.Fatal(err)
	}
	hash := data.ReconcileEffectHash(raw)
	planID := data.ReconcileEffectKey("plan", runID, hash)
	attempt := data.ReconcileEffectKey("attempt", runID, planID, step.ID)
	if len(resumedOperation) > 0 {
		attempt = data.ReconcileEffectKey("attempt-resume", runID, planID, step.ID, resumedOperation[0])
	}
	effect := data.ReconcileEffectKey("effect", attempt)
	original := integration.StepResult{DispatchState: "dispatched", VerificationState: "unknown", Value: &model.Value{Kind: model.StringValue, String: "original-bound-output"}}
	originalRaw, _ := json.Marshal(original)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	graph := &datlytest.Graph{
		Plan:     &datlytest.Plan{Namespace: ns, ID: planID, ObjectiveID: runID, ContentHash: hash, ContentJSON: string(raw), CreatedAt: now},
		Run:      &datlytest.Run{Namespace: ns, ID: runID, PlanID: planID, Status: "running", Revision: 3, SessionID: ptr("owned-session"), OperationID: ptr("owned-operation"), CreatedAt: now, UpdatedAt: now},
		Attempts: []datlytest.Attempt{{Namespace: ns, ID: attempt, RunID: runID, StepID: step.ID, PlanID: planID, LeaseEpoch: 1, State: "intent", CreatedAt: now}},
		Effects:  []datlytest.Effect{{Namespace: ns, ID: effect, AttemptID: attempt, RunID: runID, BusinessKey: "original-business-key", State: "unknown", Revision: 2, EvidenceJSON: string(originalRaw)}},
		Events:   []datlytest.Event{{Namespace: ns, ID: data.ReconcileEffectKey("intent-event", attempt), RunID: runID, AttemptID: &attempt, Sequence: 1, Kind: "intent", PayloadJSON: "{}", CreatedAt: now}, {Namespace: ns, ID: data.ReconcileEffectKey("outcome-event", attempt), RunID: runID, AttemptID: &attempt, Sequence: 2, Kind: "outcome", PayloadJSON: string(originalRaw), CreatedAt: now}},
	}
	if err = datlytest.Apply(f.ctx, f.fixtures, datlytest.Input{Namespace: ns, Mode: "graph", Graph: graph}); err != nil {
		t.Fatal(err)
	}
	result := objective.Result{Truth: objective.True, Authority: objective.Observational, ObservedAt: time.Now(), Evidence: []objective.Evidence{{Kind: "nativeUIRead", Reference: "owned-fresh-native-reference"}}}
	verified := original
	verified.VerificationState = "verified"
	verified.Postcondition = &result
	stepHash, _ := data.ReconcileEffectStepHash(step)
	a := data.ReconcileEffectAuthority{Namespace: ns, RunID: runID, PlanID: planID, StepID: step.ID, AttemptID: attempt, EffectID: effect, BusinessKey: "original-business-key", OriginalStepHash: stepHash, OriginalEvidenceJSON: string(originalRaw), RunRevision: 3, EffectRevision: 2, AuditSequence: 3, AuditID: data.ReconcileEffectKey("reconcile-event", ns, runID, effect, "fixture-request"), MilestoneID: data.ReconcileEffectKey("milestone", runID, step.ID), Now: now, Evidence: data.ReconcileEffectEvidence{ContractID: "qualified-navigation.v1", ContractHash: strings.Repeat("c", 64), RequiredAuthority: objective.Observational, FreshnessMs: 30000, Result: result, StepResult: verified}}
	guard, err := data.WithStateMutationPermit(f.ctx, ns, runID)
	if err != nil {
		t.Fatal(err)
	}
	return a, guard
}
func body(a data.ReconcileEffectAuthority) *reconcileeffect.ReconcileEffectInput {
	m := &reconcileeffect.Milestone{}
	m.SetNamespace(ptr(a.Namespace))
	m.SetId(ptr(a.MilestoneID))
	m.SetRunId(ptr(a.RunID))
	m.SetAttemptId(ptr(a.AttemptID))
	m.SetState(ptr("verified"))
	m.SetEvidenceJson(ptr(a.EvidenceJSON))
	e := &reconcileeffect.Effect{}
	e.SetNamespace(ptr(a.Namespace))
	e.SetId(ptr(a.EffectID))
	e.SetRunId(ptr(a.RunID))
	e.SetAttemptId(ptr(a.AttemptID))
	e.SetRevision(ptr(a.EffectRevision))
	e.SetState(ptr("confirmed"))
	e.SetEvidenceJson(ptr(a.EvidenceJSON))
	e.SetMilestones([]*reconcileeffect.Milestone{m})
	event := &reconcileeffect.Event{}
	event.SetNamespace(ptr(a.Namespace))
	event.SetId(ptr(a.AuditID))
	event.SetRunId(ptr(a.RunID))
	event.SetAttemptId(ptr(a.AttemptID))
	event.SetSequence(ptr(a.AuditSequence))
	event.SetKind(ptr("effect_reconciliation"))
	event.SetPayloadJson(ptr(a.AuditPayloadJSON))
	event.SetCreatedAt(ptr(a.Now))
	r := &reconcileeffect.Run{}
	r.SetNamespace(ptr(a.Namespace))
	r.SetId(ptr(a.RunID))
	r.SetRevision(ptr(a.RunRevision))
	r.SetStatus(ptr("paused"))
	r.SetUpdatedAt(ptr(a.Now))
	r.SetEffects([]*reconcileeffect.Effect{e})
	r.SetEvents([]*reconcileeffect.Event{event})
	in := &reconcileeffect.ReconcileEffectInput{}
	in.SetNamespace(a.Namespace)
	in.SetReconcileEffect([]*reconcileeffect.Run{r})
	return in
}
func (f *fixture) invoke(ctx context.Context, in *reconcileeffect.ReconcileEffectInput) (handler.Outcome, error) {
	var outcome handler.Outcome
	_, err := f.server.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/reconcileeffect", Name: "ReconcileEffect"}, Route: spec.RouteRef{Method: "PATCH", Path: "/internal/data/reconcileeffect"}}, Input: in, Completion: func(actual handler.Outcome) { outcome = actual }})
	return outcome, err
}
func (f *fixture) load(t *testing.T, run string) *loadrun.Run {
	t.Helper()
	input := &loadrun.LoadRunInput{}
	input.SetNamespace(f.principal.Namespace)
	input.SetRunID(run)
	output, err := f.server.InvokeComponent(f.ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/loadrun", Name: "LoadRun"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/loadrun"}}, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	typed, ok := output.(*loadrun.LoadRunOutput)
	if !ok || len(typed.Data) != 1 {
		t.Fatalf("generated readback shape %T", output)
	}
	return typed.Data[0]
}
func TestGeneratedReconciliationAtomicGraphAndReadback(t *testing.T) {
	f := openFixture(t)
	a, guard := f.seed(t, "success")
	// Keep a second unknown effect: confirmation of one action never clears another.
	other := data.ReconcileEffectKey("other-attempt", a.RunID)
	err := datlytest.Apply(f.ctx, f.fixtures, datlytest.Input{Namespace: a.Namespace, Mode: "graph", Graph: &datlytest.Graph{Attempts: []datlytest.Attempt{{Namespace: a.Namespace, ID: other, RunID: a.RunID, StepID: "other-step", PlanID: a.PlanID, LeaseEpoch: 1, State: "intent", CreatedAt: a.Now}}, Effects: []datlytest.Effect{{Namespace: a.Namespace, ID: data.ReconcileEffectKey("effect", other), AttemptID: other, RunID: a.RunID, BusinessKey: "other-business-key", State: "unknown", Revision: 1, EvidenceJSON: "{}"}}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := data.WithReconcileEffectAuthority(guard, a)
	if err != nil {
		t.Fatal(err)
	}
	a, err = data.RequireReconcileEffectAuthority(ctx)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := f.invoke(ctx, body(a))
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.CommitConfirmed() {
		t.Fatalf("unconfirmed atomic commit %+v", outcome)
	}
	r := f.load(t, a.RunID)
	if *r.Status != "paused" || *r.Revision != 4 || *r.EndlySessionId != "owned-session" || *r.EndlyOperationId != "owned-operation" || len(r.Milestones) != 1 || len(r.Events) != 3 || len(r.Effects) != 2 {
		t.Fatalf("committed graph changed unrelated history %+v", r)
	}
	confirmed := false
	unknown := false
	original := false
	reconciled := false
	for _, e := range r.Effects {
		if *e.Id == a.EffectID {
			confirmed = *e.State == "confirmed" && *e.Revision == 3 && *e.EvidenceJson == a.EvidenceJSON
		} else {
			unknown = *e.State == "unknown" && *e.Revision == 1
		}
	}
	for _, e := range r.Events {
		if *e.Kind == "outcome" {
			original = *e.PayloadJson == a.OriginalEvidenceJSON
		}
		if *e.Id == a.AuditID {
			var audit data.ReconcileEffectAudit
			if json.Unmarshal([]byte(*e.PayloadJson), &audit) != nil {
				t.Fatal("invalid typed reconciliation audit")
			}
			reconciled = audit.PriorRunRevision == 3 && audit.PriorEffectRevision == 2 && audit.EffectID == a.EffectID && *e.PayloadJson == a.AuditPayloadJSON
		}
	}
	if !confirmed || !unknown || !original || !reconciled {
		t.Fatal("readback did not prove one exact reconciliation and preserved original audit")
	}
	// Simulate a lost transport response: persisted exact reader evidence proves the first commit;
	// a repeated writer is rejected and cannot append another event or milestone.
	lostAuthority, lostGuard := f.seed(t, "lost-acknowledgement")
	lostContext, err := data.WithReconcileEffectAuthority(lostGuard, lostAuthority)
	if err != nil {
		t.Fatal(err)
	}
	lostAuthority, _ = data.RequireReconcileEffectAuthority(lostContext)
	committedBeforeLoss := false
	lostResponse := func() error {
		actual, writeErr := f.invoke(lostContext, body(lostAuthority))
		if writeErr != nil {
			return writeErr
		}
		committedBeforeLoss = actual.CommitConfirmed()
		return errors.New("fixture transport lost committed acknowledgement")
	}
	if err := lostResponse(); err == nil || !committedBeforeLoss {
		t.Fatal("lost response did not cover a real committed transaction")
	}
	committed := f.load(t, lostAuthority.RunID)
	if *committed.Revision != 4 || len(committed.Events) != 3 || len(committed.Milestones) != 1 {
		t.Fatal("generated readback could not reconcile lost acknowledgement")
	}
	for _, event := range committed.Events {
		if *event.Id == lostAuthority.AuditID && *event.PayloadJson != lostAuthority.AuditPayloadJSON {
			t.Fatal("committed request identity conflicts")
		}
	}
	if _, err := f.invoke(lostContext, body(lostAuthority)); err == nil {
		t.Fatal("lost acknowledgement replay appended new effect")
	}
	if _, err = f.invoke(ctx, body(a)); err == nil {
		t.Fatal("resolved effect replay mutated again")
	}
	again := f.load(t, a.RunID)
	if *again.Revision != 4 || len(again.Events) != 3 || len(again.Milestones) != 1 {
		t.Fatal("lost response replay changed immutable reconciliation")
	}
}
func TestGeneratedReconciliationRequiresPersistedResumeCorrelation(t *testing.T) {
	f := openFixture(t)
	for _, tc := range []struct {
		name, operation string
		clearSession    bool
		want            bool
	}{
		{"admitted-resume", "owned-operation", false, true},
		{"foreign-operation", "different-operation", false, false},
		{"missing-session", "owned-operation", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, guard := f.seed(t, tc.name, tc.operation)
			if tc.clearSession {
				if err := datlytest.Apply(f.ctx, f.fixtures, datlytest.Input{Namespace: a.Namespace, Mode: "missingSession", RunID: a.RunID}); err != nil {
					t.Fatal(err)
				}
			}
			ctx, err := data.WithReconcileEffectAuthority(guard, a)
			if err != nil {
				t.Fatal(err)
			}
			a, err = data.RequireReconcileEffectAuthority(ctx)
			if err != nil {
				t.Fatal(err)
			}
			outcome, err := f.invoke(ctx, body(a))
			if tc.want {
				if err != nil || !outcome.CommitConfirmed() {
					t.Fatalf("admitted resumed outcome failed: %v", err)
				}
			} else if err == nil {
				t.Fatal("unrelated resumed attempt adopted")
			}
			run := f.load(t, a.RunID)
			want := "unknown"
			if tc.want {
				want = "confirmed"
			}
			if len(run.Effects) != 1 || run.Effects[0].State == nil || *run.Effects[0].State != want {
				t.Fatal("wrong persisted disposition")
			}
		})
	}
}

func TestGeneratedReconciliationRejectsForgedIngressAndCAS(t *testing.T) {
	f := openFixture(t)
	cases := []struct {
		name      string
		authority func(*data.ReconcileEffectAuthority)
		mutate    func(*reconcileeffect.ReconcileEffectInput)
		omit      bool
	}{
		{name: "no-authority", omit: true},
		{name: "stale-run", authority: func(a *data.ReconcileEffectAuthority) { a.RunRevision = 2 }},
		{name: "stale-effect", authority: func(a *data.ReconcileEffectAuthority) { a.EffectRevision = 1 }},
		{name: "wrong-step", authority: func(a *data.ReconcileEffectAuthority) { a.OriginalStepHash = strings.Repeat("d", 64) }},
		{name: "changed-business", authority: func(a *data.ReconcileEffectAuthority) { a.BusinessKey = "other-key" }},
		{name: "changed-original", authority: func(a *data.ReconcileEffectAuthority) {
			a.OriginalEvidenceJSON = `{"dispatchState":"dispatched","verificationState":"unknown","value":{"kind":"string","string":"other"}}`
			a.Evidence.StepResult.Value = &model.Value{Kind: model.StringValue, String: "other"}
		}},
		{name: "foreign-namespace", mutate: func(in *reconcileeffect.ReconcileEffectInput) {
			in.ReconcileEffect[0].Effects[0].Milestones[0].SetNamespace(ptr(strings.Repeat("b", 64)))
		}},
		{name: "foreign-attempt", mutate: func(in *reconcileeffect.ReconcileEffectInput) {
			in.ReconcileEffect[0].Effects[0].SetAttemptId(ptr("other"))
		}},
		{name: "forged-evidence", mutate: func(in *reconcileeffect.ReconcileEffectInput) {
			in.ReconcileEffect[0].Effects[0].SetEvidenceJson(ptr(`{"verificationState":"verified"}`))
		}},
		{name: "overwrite-plan", mutate: func(in *reconcileeffect.ReconcileEffectInput) { in.ReconcileEffect[0].SetPlanId(ptr("other-plan")) }},
		{name: "event-cursor", authority: func(a *data.ReconcileEffectAuthority) { a.AuditSequence = 2 }},
		{name: "absent", mutate: func(in *reconcileeffect.ReconcileEffectInput) {
			in.ReconcileEffect[0].Effects[0].SetState(ptr("absent"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, guard := f.seed(t, tc.name)
			if tc.authority != nil {
				tc.authority(&a)
			}
			ctx, err := data.WithReconcileEffectAuthority(guard, a)
			if err != nil {
				t.Fatal(err)
			}
			a, _ = data.RequireReconcileEffectAuthority(ctx)
			in := body(a)
			if tc.mutate != nil {
				tc.mutate(in)
			}
			if tc.omit {
				ctx = guard
			}
			if _, err = f.invoke(ctx, in); err == nil {
				t.Fatal("forged/CAS request committed")
			}
			r := f.load(t, a.RunID)
			if *r.Status != "running" || *r.Revision != 3 || len(r.Milestones) != 0 || len(r.Events) != 2 || *r.Effects[0].State != "unknown" || *r.Effects[0].Revision != 2 {
				t.Fatal("failed graph did not roll back atomically")
			}
		})
	}
}
func TestReconcileAuthorityRejectsUnqualifiedOrMutableProof(t *testing.T) {
	f := openFixture(t)
	a, guard := f.seed(t, "authority")
	if _, err := data.WithReconcileEffectAuthority(f.ctx, a); err == nil {
		t.Fatal("missing runtime guard minted authority")
	}
	for _, change := range []func(*data.ReconcileEffectAuthority){
		func(a *data.ReconcileEffectAuthority) {
			a.Evidence.Result.Truth = objective.False
			a.Evidence.StepResult.Postcondition = &a.Evidence.Result
		},
		func(a *data.ReconcileEffectAuthority) { a.Evidence.RequiredAuthority = objective.Authoritative },
		func(a *data.ReconcileEffectAuthority) {
			a.Evidence.Result.ObservedAt = time.Now().Add(-time.Minute)
			a.Evidence.StepResult.Postcondition = &a.Evidence.Result
		},
		func(a *data.ReconcileEffectAuthority) {
			a.Evidence.Result.Evidence = nil
			a.Evidence.StepResult.Postcondition = &a.Evidence.Result
		},
		func(a *data.ReconcileEffectAuthority) {
			a.Evidence.StepResult.Value = &model.Value{Kind: model.StringValue, String: "invented"}
		},
	} {
		copy := a
		copy.Evidence.StepResult.Postcondition = nil
		result := copy.Evidence.Result
		copy.Evidence.StepResult.Postcondition = &result
		change(&copy)
		if _, err := data.WithReconcileEffectAuthority(guard, copy); err == nil {
			t.Fatal("invalid proof minted authority")
		}
	}
	ctx, err := data.WithReconcileEffectAuthority(guard, a)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := data.RequireReconcileEffectAuthority(ctx)
	a.Evidence.Result.Evidence[0].Reference = "mutated-client-reference"
	*a.Evidence.StepResult.Value = model.Value{Kind: model.StringValue, String: "mutated-output"}
	current, err := data.RequireReconcileEffectAuthority(ctx)
	if err != nil || !reflect.DeepEqual(current, expected) {
		t.Fatal("caller mutation changed trusted evaluation capability")
	}
}

func TestGeneratedReconciliationConcurrentCASWinner(t *testing.T) {
	f := openFixture(t)
	a, guard := f.seed(t, "concurrent-cas")
	ctx, err := data.WithReconcileEffectAuthority(guard, a)
	if err != nil {
		t.Fatal(err)
	}
	a, _ = data.RequireReconcileEffectAuthority(ctx)
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcome, err := f.invoke(ctx, body(a))
			results <- err == nil && outcome.CommitConfirmed()
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for won := range results {
		if won {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("expected one CAS winner, got %d", wins)
	}
	current := f.load(t, a.RunID)
	if *current.Revision != 4 || len(current.Events) != 3 || len(current.Milestones) != 1 || *current.Effects[0].Revision != 3 {
		t.Fatal("concurrent reconciliation duplicated progress")
	}
}
