package recovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/mechanize/data/recoveryload"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	core "github.com/viant/mechanize/recovery"
)

func recoveryFixture(t *testing.T) (context.Context, auth.Principal, *recoveryload.RecoveryRun, Options) {
	t.Helper()
	p, err := auth.NewPrincipal("fixture", "", "repair-alice", []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	surface := model.Surface{Kind: "native", BundleID: "fixture.editor"}
	predicate := &model.Predicate{Kind: "adapter", Adapter: "fixture", Name: "saved", Scope: model.PredicateScope{SurfaceRef: "app"}, TimeoutMs: 100, FreshnessMs: 100, RequiredAuthority: "authoritative"}
	key := func(phase string) map[string]model.Value {
		return map[string]model.Value{"case": {Kind: model.ReferenceValue, Ref: "input.case"}, "phase": {Kind: model.StringValue, String: phase}}
	}
	target := model.Selector{Surface: surface, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "old-save"}, Exact: true}}
	first := model.Step{ID: "save", Action: "element.press", Target: target, TimeoutMs: 100, SemanticsProfile: "save.v1", Postcondition: predicate, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: key("save"), Reconcile: predicate}}
	second := first
	second.ID = "finish"
	second.SemanticsProfile = "finish.v1"
	second.Effect.BusinessKey = key("finish")
	plan := model.Plan{SchemaVersion: 1, Surfaces: map[string]model.Surface{"app": surface}, Objective: predicate, Constraints: &model.Constraints{AllowedApps: []string{surface.BundleID}}, Recovery: &model.RecoveryPolicy{MaxRepairs: 2, MaxElapsedMs: 2000, OnUnknownEffect: "needsAttention"}, Requires: &model.Requirements{Adapters: []string{"fixture"}, SemanticsProfiles: []string{"save.v1", "finish.v1", "observe.v1"}}, Inputs: map[string]model.InputDefinition{"case": {Type: model.StringValue, Required: true}, "password": {Type: model.StringValue, Sensitive: true}}, Steps: []model.Step{first, second}}
	inputs := map[string]model.Value{"case": {Kind: model.StringValue, String: "case-1"}, "password": {Kind: model.StringValue, String: "fixture-password-never-to-planner"}}
	envelope, _ := json.Marshal(planEnvelope{Plan: plan, Inputs: inputs})
	ns, runID, planID, objectiveID, created := p.Namespace, "run", "original-plan", "objective", time.Now().UTC().Format(time.RFC3339Nano)
	attemptID, effectID := "original-save-attempt", "original-save-effect"
	business, _ := canonicalKey(first.Effect.BusinessKey, map[string]model.Value{"input.case": inputs["case"]})
	result, _ := json.Marshal(integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"})
	row := &recoveryload.RecoveryRun{Namespace: &ns, Id: &runID, PlanId: &planID, ObjectiveId: &objectiveID, Status: ptr("paused"), Revision: ptr(3), CreatedAt: &created, UpdatedAt: &created, Plans: []*recoveryload.PlanRevision{{Namespace: &ns, Id: &planID, ObjectiveId: &objectiveID, ContentHash: ptr(digest(envelope)), ContentJson: ptr(string(envelope)), CreatedAt: &created}}, Attempts: []*recoveryload.Attempt{{Namespace: &ns, Id: &attemptID, RunId: &runID, StepId: ptr(first.ID), PlanId: &planID, LeaseEpoch: ptr(1), State: ptr("intent"), CreatedAt: &created}}, Effects: []*recoveryload.Effect{{Namespace: &ns, Id: &effectID, RunId: &runID, AttemptId: &attemptID, BusinessKey: &business, State: ptr("confirmed"), Revision: ptr(2), EvidenceJson: ptr(string(result))}}, Milestones: []*recoveryload.Milestone{{Namespace: &ns, Id: ptr("original-milestone"), RunId: &runID, AttemptId: &attemptID, State: ptr("verified"), EvidenceJson: ptr(string(result))}}}
	opts := Options{Authorize: func(_ context.Context, actual auth.Principal, s model.Surface) error {
		if actual.Namespace != p.Namespace || s.Kind != "" && s != surface {
			return auth.ErrUnauthorized
		}
		return nil
	}, Guard: func(context.Context, auth.Principal, RunReference) (func() error, error) {
		return func() error { return nil }, nil
	}, RuntimeReady: func(context.Context, auth.Principal) error { return nil }, IncidentMaxRepairs: 2, IncidentMaxElapsedMs: 2000}
	opts.PrepareEvidence = func(_ context.Context, _ auth.Principal, snapshot Snapshot) (Evidence, error) {
		now := time.Now()
		return Evidence{Verified: true, Redacted: true, PolicyHash: "fixture-policy", ValidUntil: now.Add(4 * time.Second), Observation: model.Observation{Surface: surface, Started: now.Add(-time.Millisecond), Ended: now, Epoch: "live-epoch-not-for-planner", Nodes: []model.Node{{Ref: model.ElementRef{ID: "live-handle", Epoch: "live-epoch"}, Role: "button", Identifier: "changed-save", Values: map[string]model.Value{"value": inputs["password"]}}}}, EvidenceRefs: []string{"owned-redacted-evidence"}, Contracts: []core.Contract{{Profile: "finish.v1", Action: second.Action, Surface: surface, Permissions: []string{"desktop:control"}, Qualified: true, Postcondition: predicate, Reconcile: predicate}, {Profile: "observe.v1", Action: "element.read", Surface: surface, Permissions: []string{"desktop:control"}, Qualified: true}}}, nil
	}
	opts.VerifyEvidence = func(_ context.Context, _ auth.Principal, _ Snapshot, e Evidence) error {
		if !e.Verified || !e.Redacted || time.Now().After(e.ValidUntil) {
			return errors.New("stale/unverified evidence")
		}
		return nil
	}
	return auth.WithPrincipal(context.Background(), p), p, row, opts
}
func scopedMemory(row *recoveryload.RecoveryRun) func(context.Context, auth.Principal, exec.ComponentRequest) (any, error) {
	return func(_ context.Context, p auth.Principal, request exec.ComponentRequest) (any, error) {
		input, ok := request.Input.(*recoveryload.LoadRecoveryInput)
		if !ok {
			return nil, errors.New("fixture mutation is not allowed")
		}
		if input.Namespace != p.Namespace || row.Namespace == nil || *row.Namespace != p.Namespace {
			return nil, auth.ErrUnauthorized
		}
		return &recoveryload.LoadRecoveryOutput{Data: []*recoveryload.RecoveryRun{row}}, nil
	}
}
func requestFrom(snapshot Snapshot) ContextRequest {
	return ContextRequest{RunID: snapshot.Reference.RunID, ExpectedRevision: snapshot.Reference.Revision, ExpectedPlanID: snapshot.Reference.PlanID}
}
func patchFrom(snapshot Snapshot) core.PlanPatch {
	step := snapshot.Plan.Steps[snapshot.CompletedSteps]
	step.Target.Locator = &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "changed-save"}, Exact: true}
	return core.PlanPatch{BaseHash: snapshot.Reference.PlanHash, ObjectiveHash: snapshot.Reference.ObjectiveHash, RemainingSteps: []model.Step{step}, EvidenceRefs: []string{"owned-redacted-evidence"}}
}
func TestRecoveryContextRedactionUnknownAndAuthorityDefaults(t *testing.T) {
	ctx, p, row, opts := recoveryFixture(t)
	opts.Invoke = scopedMemory(row)
	service, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Snapshot(ctx, p, "run")
	if err != nil || snapshot.CompletedSteps != 1 {
		t.Fatalf("snapshot %+v %v", snapshot.Reference, err)
	}
	result, err := service.Context(ctx, p, requestFrom(snapshot))
	if err != nil || result.Status != "ready" || result.Context == nil {
		t.Fatalf("%+v %v", result, err)
	}
	encoded, _ := json.Marshal(result)
	for _, secret := range []string{"fixture-password-never-to-planner", "live-handle", "live-epoch"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("planner context leaked %s", secret)
		}
	}
	if len(result.Context.View.Bindings) != 0 {
		t.Fatal("live bindings exposed")
	}
	unavailable := opts
	unavailable.PrepareEvidence = nil
	defaultService, _ := New(unavailable)
	result, err = defaultService.Context(ctx, p, requestFrom(snapshot))
	if err != nil || result.Status != "needsAttention" || result.Context != nil {
		t.Fatalf("unqualified default %+v %v", result, err)
	}
	row.Effects[0].State = ptr("unknown")
	calls := 0
	opts.PrepareEvidence = func(context.Context, auth.Principal, Snapshot) (Evidence, error) { calls++; return Evidence{}, nil }
	service, _ = New(opts)
	result, err = service.Context(ctx, p, requestFrom(snapshot))
	if err != nil || result.Status != "needsAttention" || calls != 0 {
		t.Fatalf("unknown effect reached evidence/planner %+v %v calls%d", result, err, calls)
	}
}
func TestRepairSnapshotRequiresContiguousOriginalPrefix(t *testing.T) {
	ctx, p, row, opts := recoveryFixture(t)
	opts.Invoke = scopedMemory(row)
	var env planEnvelope
	_ = json.Unmarshal([]byte(*row.Plans[0].ContentJson), &env)
	read := model.Step{ID: "unrecorded-read", Action: "element.read", Target: env.Plan.Steps[0].Target, Arguments: map[string]model.Value{"attribute": {Kind: model.StringValue, String: "text"}}, TimeoutMs: 100, Effect: model.Effect{Class: model.ReadOnly}}
	env.Plan.Steps = append([]model.Step{read}, env.Plan.Steps...)
	body, _ := json.Marshal(env)
	row.Plans[0].ContentJson = ptr(string(body))
	row.Plans[0].ContentHash = ptr(digest(body))
	service, _ := New(opts)
	if _, err := service.Snapshot(ctx, p, "run"); err == nil {
		t.Fatal("unrecorded readonly prefix fabricated")
	}
}
func TestRepairPatchChangedLocatorDialogAndHardGates(t *testing.T) {
	ctx, p, row, opts := recoveryFixture(t)
	opts.Invoke = scopedMemory(row)
	service, _ := New(opts)
	snapshot, err := service.Snapshot(ctx, p, "run")
	if err != nil {
		t.Fatal(err)
	}
	private, _, err := service.prepare(ctx, p, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	patch := patchFrom(snapshot)
	if _, err = core.Validate(ctx, private, patch); err != nil {
		t.Fatalf("held-out locator change: %v", err)
	}
	dialog := model.Step{ID: "inspect-extra-dialog", Action: "element.read", Target: patch.RemainingSteps[0].Target, Arguments: map[string]model.Value{"attribute": {Kind: model.StringValue, String: "text"}}, TimeoutMs: 100, SemanticsProfile: "observe.v1", Effect: model.Effect{Class: model.ReadOnly}}
	patch.RemainingSteps = append([]model.Step{dialog}, patch.RemainingSteps...)
	if _, err = core.Validate(ctx, private, patch); err != nil {
		t.Fatalf("qualified extra-dialog read: %v", err)
	}
	for _, name := range []string{"objective", "key", "skip", "unqualified", "budget"} {
		t.Run(name, func(t *testing.T) {
			candidate := patchFrom(snapshot)
			frame := private
			switch name {
			case "objective":
				candidate.ObjectiveHash = core.Hash("different")
			case "key":
				candidate.RemainingSteps[0].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: "different-case"}}
			case "skip":
				candidate.RemainingSteps = []model.Step{dialog}
			case "unqualified":
				frame.Contracts = nil
			case "budget":
				frame.IncidentBudget.UsedRepairs = frame.IncidentBudget.MaxRepairs
			}
			if _, err := core.Validate(ctx, frame, candidate); err == nil {
				t.Fatal("unsafe repair accepted")
			}
		})
	}
}

// Seed setup is infrastructure/test-only SQL. Behavioral admission and all
// verification reads below execute actual generated Datly use-case components.
func seedRecovery(t *testing.T, ctx context.Context, p auth.Principal, root string, row *recoveryload.RecoveryRun) {
	t.Helper()
	scoped, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := data.Provision(scoped, root, data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", cfg.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	plan := row.Plans[0]
	if _, err = db.ExecContext(ctx, "INSERT INTO plan_revisions(namespace,id,objective_id,content_hash,content_json,created_at) VALUES(?,?,?,?,?,?)", *plan.Namespace, *plan.Id, *plan.ObjectiveId, *plan.ContentHash, *plan.ContentJson, *plan.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO runs(namespace,id,plan_id,status,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", *row.Namespace, *row.Id, *row.PlanId, *row.Status, *row.Revision, *row.CreatedAt, *row.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	for _, attempt := range row.Attempts {
		if _, err = db.ExecContext(ctx, "INSERT INTO attempts(namespace,id,run_id,step_id,plan_id,lease_epoch,state,created_at) VALUES(?,?,?,?,?,?,?,?)", *attempt.Namespace, *attempt.Id, *attempt.RunId, *attempt.StepId, *attempt.PlanId, *attempt.LeaseEpoch, *attempt.State, *attempt.CreatedAt); err != nil {
			t.Fatal(err)
		}
	}
	for _, effect := range row.Effects {
		if _, err = db.ExecContext(ctx, "INSERT INTO effects(namespace,id,attempt_id,run_id,business_key,state,revision,evidence_json) VALUES(?,?,?,?,?,?,?,?)", *effect.Namespace, *effect.Id, *effect.AttemptId, *effect.RunId, *effect.BusinessKey, *effect.State, *effect.Revision, *effect.EvidenceJson); err != nil {
			t.Fatal(err)
		}
	}
	for _, milestone := range row.Milestones {
		if _, err = db.ExecContext(ctx, "INSERT INTO milestones(namespace,id,run_id,attempt_id,state,evidence_json) VALUES(?,?,?,?,?,?)", *milestone.Namespace, *milestone.Id, *milestone.RunId, *milestone.AttemptId, *milestone.State, *milestone.EvidenceJson); err != nil {
			t.Fatal(err)
		}
	}
}
func TestGeneratedRepairAdmissionAtomicLineageCASBudgetAndAcknowledgement(t *testing.T) {
	ctx, p, row, opts := recoveryFixture(t)
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	storage := t.TempDir()
	seedRecovery(t, ctx, p, storage, row)
	scoped, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	server, err := datahost.Open(scoped, source, storage, data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	opts.Invoke = func(ctx context.Context, p auth.Principal, r exec.ComponentRequest) (any, error) {
		bound, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
		if err != nil {
			return nil, err
		}
		return server.InvokeComponent(bound, r)
	}
	guardHeld := false
	cleanupErr := errors.New("fixture guard cleanup unconfirmed")
	var releaseErr error = cleanupErr
	guardCalls, guardReleases := 0, 0
	preparations := 0
	opts.PrepareAdmission = func(ctx context.Context, _ auth.Principal) error {
		if !guardHeld {
			return errors.New("writer preparation outside admission guard")
		}
		preparations++
		return server.PrepareComponent(ctx, spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/repairadmit", Name: "AdmitRepair"})
	}
	prepareEvidence := opts.PrepareEvidence
	opts.PrepareEvidence = func(ctx context.Context, p auth.Principal, snapshot Snapshot) (Evidence, error) {
		if !guardHeld || preparations == 0 {
			return Evidence{}, errors.New("evidence collected before guarded writer preparation")
		}
		return prepareEvidence(ctx, p, snapshot)
	}
	opts.Guard = func(context.Context, auth.Principal, RunReference) (func() error, error) {
		guardCalls++
		guardHeld = true
		return func() error { guardHeld = false; guardReleases++; return releaseErr }, nil
	}
	opts.RuntimeReady = func(context.Context, auth.Principal) error {
		if !guardHeld {
			return errors.New("readiness checked outside admission guard")
		}
		return nil
	}
	service, _ := New(opts)
	snapshot, err := service.Snapshot(ctx, p, "run")
	if err != nil {
		t.Fatal(err)
	}
	patch := patchFrom(snapshot)
	body, _ := json.Marshal(patch)
	request := AdmissionRequest{ContextRequest: requestFrom(snapshot), Patch: body}
	admitted, err := service.Admit(ctx, p, request)
	if !errors.Is(err, cleanupErr) || !admitted.CommitConfirmed || admitted.ReadyToResume || admitted.Status != "needsAttention" || admitted.Reference == nil || guardHeld {
		t.Fatalf("admission %+v %v", admitted, err)
	}
	releaseErr = nil
	after, err := service.Snapshot(ctx, p, "run")
	if err != nil || after.CompletedSteps != 1 || len(after.Lineage) != 1 || after.Lineage[0].OriginalPlanID != snapshot.Reference.PlanID || after.Lineage[0].AttemptID != *row.Attempts[0].Id || after.Reference.PlanID != admitted.Reference.NewPlanID {
		t.Fatalf("lineage %+v %v", after, err)
	}
	if len(after.Raw.Attempts) != 1 || *after.Raw.Attempts[0].PlanId != snapshot.Reference.PlanID || len(after.Raw.Effects) != 1 || after.Raw.Workflow == nil || value(after.Raw.Workflow.UsedRepairs) != 1 {
		t.Fatal("old ledger relabelled or budget not consumed")
	}
	replay, err := service.Admit(ctx, p, request)
	if err != nil || !replay.CommitConfirmed || !replay.ReadyToResume || *replay.Reference != *admitted.Reference || guardCalls != 2 || guardReleases != 2 || preparations != 1 || guardHeld {
		t.Fatalf("repair replay %+v %v", replay, err)
	}
	t.Run("committed replay guard refusal preserves history", func(t *testing.T) {
		for _, mode := range []string{"missing", "rejected", "nil release", "cleanup failure", "state changed under guard"} {
			t.Run(mode, func(t *testing.T) {
				blockedOpts := opts
				rejected := errors.New("fixture operation active")
				switch mode {
				case "missing":
					blockedOpts.Guard = nil
				case "rejected":
					blockedOpts.Guard = func(context.Context, auth.Principal, RunReference) (func() error, error) { return nil, rejected }
				case "nil release":
					blockedOpts.Guard = func(context.Context, auth.Principal, RunReference) (func() error, error) { return nil, nil }
				case "cleanup failure":
					releaseErr = cleanupErr
				case "state changed under guard":
					var changed recoveryload.RecoveryRun
					encoded, _ := json.Marshal(after.Raw)
					if err := json.Unmarshal(encoded, &changed); err != nil {
						t.Fatal(err)
					}
					blockedOpts.Invoke = scopedMemory(&changed)
					blockedOpts.Guard = func(context.Context, auth.Principal, RunReference) (func() error, error) {
						changed.Status = ptr("running")
						return func() error { return nil }, nil
					}
				}
				blocked, _ := New(blockedOpts)
				result, err := blocked.Admit(ctx, p, request)
				releaseErr = nil
				if !result.CommitConfirmed || result.Reference == nil || *result.Reference != *admitted.Reference || result.ReadyToResume || result.Status != "needsAttention" || guardHeld {
					t.Fatalf("unsafe replay result: %+v %v", result, err)
				}
				if mode == "rejected" && !errors.Is(err, rejected) || mode == "cleanup failure" && !errors.Is(err, cleanupErr) || mode == "nil release" && err == nil {
					t.Fatalf("guard failure lost: %v", err)
				}
				unchanged, err := service.Snapshot(ctx, p, "run")
				if err != nil || !reflect.DeepEqual(after.Raw, unchanged.Raw) {
					t.Fatal("guard refusal or cleanup changed revision, audit, lineage, or budgets")
				}
			})
		}
	})
	changed := request
	different := patch
	different.RemainingSteps[0].Target.Locator.Value.String = "another-selector"
	changed.Patch, _ = json.Marshal(different)
	stale, err := service.Admit(ctx, p, changed)
	if err != nil || stale.CommitConfirmed || stale.Status != "needsAttention" {
		t.Fatalf("stale CAS %+v %v", stale, err)
	}
	// A second immutable revision consumes the remaining finite budget. Simulate
	// acknowledgement loss after a real generated commit; only later exact read
	// reconciliation can permit resume.
	next := patchFrom(after)
	next.RemainingSteps[0].Target.Locator.Value.String = "held-out-next-selector"
	nextBody, _ := json.Marshal(next)
	nextRequest := AdmissionRequest{ContextRequest: requestFrom(after), Patch: nextBody}
	realInvoke := opts.Invoke
	opts.Invoke = func(ctx context.Context, p auth.Principal, r exec.ComponentRequest) (any, error) {
		value, err := realInvoke(ctx, p, r)
		if err == nil && r.Target.Component.Name == "AdmitRepair" {
			return nil, errors.New("injected committed acknowledgement loss")
		}
		return value, err
	}
	uncertainService, _ := New(opts)
	uncertain, err := uncertainService.Admit(ctx, p, nextRequest)
	if err == nil || uncertain.Reference == nil || uncertain.CommitConfirmed || uncertain.ReadyToResume || uncertain.Status != "needsAttention" {
		t.Fatalf("uncertain admission %+v %v", uncertain, err)
	}
	reconciled, err := service.Admit(ctx, p, nextRequest)
	if err != nil || !reconciled.CommitConfirmed || !reconciled.ReadyToResume || *reconciled.Reference != *uncertain.Reference {
		t.Fatalf("scoped reconciliation %+v %v", reconciled, err)
	}
	final, err := service.Snapshot(ctx, p, "run")
	if err != nil {
		t.Fatal(err)
	}
	exhausted, err := service.Context(ctx, p, requestFrom(final))
	if err != nil || exhausted.Status != "needsAttention" || exhausted.Context != nil {
		t.Fatalf("budget exhaustion %+v %v", exhausted, err)
	}
}
