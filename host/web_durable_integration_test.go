package host

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func TestWebGeneratedIntentPrecedesPinnedDispatchWithoutNativeFence(t *testing.T) {
	f := newWebControlFixture(t)
	h := &Host{webControl: f.manager, users: map[string]User{f.principal.Namespace: {WebOrigins: []string{"https://fixture.test"}}}}
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Dir(filepath.Dir(file))
	storage := t.TempDir()
	nativeFenceCalls := 0
	store, err := durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) {
		nativeFenceCalls++
		return 0, errors.New("native fence forbidden for renderer")
	}, PrepareStepAuthority: h.prepareStepExecutor}, h.execute)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close(context.Background())
	observer, err := durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 0, errors.New("observer cannot dispatch") }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		return automation.StepResult{}, errors.New("observer cannot dispatch")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	runner, err := automation.NewWithOptions(store.Execute, automation.Options{PreparePlan: store.PreparePlan, EvaluatePostcondition: store.EvaluatePostcondition, CompleteObjective: store.CompleteObjective, AttachInitialOperation: func(ctx context.Context, p auth.Principal, runID string, revision int, sessionID, operationID string) error {
		_, err := store.AttachOperation(ctx, p, runID, revision, sessionID, operationID)
		return err
	}})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := runner.Open(f.ctx, "generated web intent fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close(f.ctx, opened.SessionID)
	ctx := auth.WithConsentBinding(f.ctx, auth.ConsentBinding{GrantID: "fixture-grant", SessionID: opened.SessionID, Purpose: "fixture purpose"})
	sawCommittedIntent := false
	f.manager.options.ExecutePinned = func(ctx context.Context, p auth.Principal, step model.Step, _ map[string]model.Value, authority WebControlAuthority) (automation.StepResult, error) {
		metadata, ok := automation.ExecutionFromContext(ctx)
		if !ok || authority != f.ready.Authority {
			return automation.StepResult{}, errors.New("pinned executor or Endly metadata missing")
		}
		state, err := observer.StateGet(auth.WithPrincipal(context.Background(), p), p, metadata.RunID)
		if err != nil || len(state.UnresolvedEffects) != 1 {
			return automation.StepResult{}, errors.Join(err, errors.New("generated committed intent absent before browser effect"))
		}
		sawCommittedIntent = true
		return automation.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	}
	step := f.step
	// Press retains its conservative external effect and explicit fixture key.
	step.Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: "fixture-case-1"}}
	op, err := runner.StartPlan(ctx, opened.SessionID, model.Plan{SchemaVersion: 1, Steps: []model.Step{step}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	finished, err := runner.Wait(deadline, opened.SessionID, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !sawCommittedIntent || nativeFenceCalls != 0 || finished.Status != "failed" {
		t.Fatalf("intent=%v nativeFence=%d outcome=%+v", sawCommittedIntent, nativeFenceCalls, finished)
	}
	// The receipt alone cannot prove the effect or authorize replay.
	business, err := runner.Result(ctx, opened.SessionID, op.ID)
	if err != nil || business.BusinessStatus != "unverified" || business.VerificationState != "unknown" {
		t.Fatalf("receipt promoted to business success: %+v %v", business, err)
	}
	id, err := runner.RunReference(ctx, opened.SessionID, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := observer.StateGet(auth.WithPrincipal(context.Background(), f.principal), f.principal, id)
	if err != nil || len(state.UnresolvedEffects) != 1 || len(state.Progress) != 0 {
		t.Fatalf("browser uncertainty barrier lost: %+v %v", state, err)
	}
}
