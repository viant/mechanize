package durable

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/loadrun"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

// This fixture exercises the generated reader/writer graph against an isolated
// database. Its only dispatched action is an injected uncertain native receipt.
func TestGeneratedStopBoundaryPreservesUnknownAndNeverAdmitsResume(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, err := auth.NewPrincipal("fixture:issuer", "", "stop-boundary", []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), p)
	var dispatches atomic.Int32
	guardCalls, releases := 0, 0
	var guardErr, releaseErr error
	var b *Builder
	b, err = New(Options{
		SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(),
		LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil },
		ReconciliationGuard: func(_ context.Context, got auth.Principal, runID string) (func() error, error) {
			guardCalls++
			if got.Namespace != p.Namespace || runID == "" {
				return nil, errors.New("guard correlation missing")
			}
			if guardErr != nil {
				return nil, guardErr
			}
			return func() error { releases++; return releaseErr }, nil
		},
	}, func(ctx context.Context, p auth.Principal, _ model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		metadata, ok := integration.ExecutionFromContext(ctx)
		if !ok {
			return integration.StepResult{}, errors.New("dispatch lacks durable execution identity")
		}
		bound, user, err := b.bound(ctx, p, 0)
		if err != nil {
			return integration.StepResult{}, err
		}
		persisted, err := load(bound, user.server, p, metadata.RunID)
		if err != nil {
			return integration.StepResult{}, err
		}
		if persisted.EndlySessionId == nil || persisted.EndlyOperationId == nil || *persisted.EndlySessionId != metadata.SessionID || *persisted.EndlyOperationId != metadata.OperationID {
			return integration.StepResult{}, errors.New("native dispatch preceded exact persisted Endly correlation")
		}
		dispatches.Add(1)
		return integration.StepResult{DispatchState: "dispatched", VerificationState: "unknown"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	r, err := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, runID string, revision int, sessionID, operationID string) error {
		_, err := b.AttachOperation(ctx, p, runID, revision, sessionID, operationID)
		return err
	}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "stopped boundary fixture")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := script.Compile(`app("com.example.Fixture", processId: 42, processStartToken: "1790000000:1").getById("save", exact: true).click()`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Steps[0].TimeoutMs = 120000
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"task": {Kind: model.StringValue, String: "stop-fixture"}}
	op, err := r.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	if _, err = r.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	runID, err := r.RunReference(ctx, session.SessionID, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	read := func() *loadrun.Run {
		t.Helper()
		bound, user, err := b.bound(ctx, p, 0)
		if err != nil {
			t.Fatal(err)
		}
		user.mu.Lock()
		defer user.mu.Unlock()
		run, err := load(bound, user.server, p, runID)
		if err != nil {
			t.Fatal(err)
		}
		return run
	}
	state, err := b.StateGet(ctx, p, runID)
	if err != nil {
		t.Fatal(err)
	}
	before := read()
	if len(before.Effects) != 1 || before.Effects[0].State == nil || *before.Effects[0].State != "unknown" || len(state.UnresolvedEffects) != 1 || dispatches.Load() != 1 {
		t.Fatalf("fixture did not persist exactly one uncertain dispatch: %+v", state)
	}
	assertHistory := func(after *loadrun.Run, boundaries int) {
		t.Helper()
		if !reflect.DeepEqual(before.Effects, after.Effects) || !reflect.DeepEqual(before.Attempts, after.Attempts) || !reflect.DeepEqual(before.Milestones, after.Milestones) {
			t.Fatal("stopped boundary modified effect, attempt, or milestone history")
		}
		if !reflect.DeepEqual(before.Plan, after.Plan) || !reflect.DeepEqual(before.EndlySessionId, after.EndlySessionId) || !reflect.DeepEqual(before.EndlyOperationId, after.EndlyOperationId) {
			t.Fatal("stopped boundary modified immutable plan or Endly correlation")
		}
		original := make(map[string]*loadrun.Event)
		outcomes := 0
		for _, e := range before.Events {
			original[*e.Id] = e
			if e.Kind != nil && *e.Kind == "outcome" {
				outcomes++
				var receipt integration.StepResult
				if e.PayloadJson == nil || json.Unmarshal([]byte(*e.PayloadJson), &receipt) != nil || receipt.VerificationState != "unknown" {
					t.Fatal("fixture lacks original unknown outcome")
				}
			}
		}
		if outcomes != 1 {
			t.Fatalf("expected one original outcome, got %d", outcomes)
		}
		count := 0
		for _, e := range after.Events {
			if old, ok := original[*e.Id]; ok {
				if !reflect.DeepEqual(old, e) {
					t.Fatal("original audit was rewritten")
				}
				delete(original, *e.Id)
			} else if e.Kind != nil && *e.Kind == "stopped_boundary" {
				count++
			} else {
				t.Fatal("unexpected appended event")
			}
		}
		if len(original) != 0 || count != boundaries || dispatches.Load() != 1 {
			t.Fatalf("history/dispatch mismatch: missing=%d boundaries=%d dispatches=%d", len(original), count, dispatches.Load())
		}
	}
	req := StopBoundaryRequest{RunID: runID, PlanID: state.PlanID, RequestID: "boundary-1", ExpectedRunRevision: state.Revision}

	t.Run("guard rejection leaves database unchanged", func(t *testing.T) {
		guardErr = errors.New("native operation still active")
		result, err := b.StopBoundary(ctx, p, req)
		if !errors.Is(err, guardErr) || result.CommitConfirmed || releases != 0 {
			t.Fatalf("guard rejection: %+v %v", result, err)
		}
		if !reflect.DeepEqual(before, read()) {
			t.Fatal("guard rejection mutated durable run")
		}
		guardErr = nil
	})
	var committed StopBoundaryResult
	t.Run("paused CAS preserves uncertainty and audit", func(t *testing.T) {
		committed, err = b.StopBoundary(ctx, p, req)
		if err != nil {
			t.Fatal(err)
		}
		if !committed.CommitConfirmed || committed.ResumeAdmitted || committed.Run == nil || committed.Run.Status != "paused" || committed.Run.Revision != state.Revision+1 || !committed.Run.NeedsAttention || !reflect.DeepEqual(committed.Run.UnresolvedEffectIDs, []string{*before.Effects[0].Id}) {
			t.Fatalf("invalid boundary projection: %+v", committed)
		}
		after := read()
		assertHistory(after, 1)
		if *after.Status != "paused" || *after.Revision != state.Revision+1 {
			t.Fatal("paused CAS not persisted")
		}
		found := false
		for _, event := range after.Events {
			if *event.Id != committed.BoundaryID {
				continue
			}
			found = true
			var audit data.StopBoundaryAudit
			if event.AttemptId != nil || *event.Kind != "stopped_boundary" || json.Unmarshal([]byte(*event.PayloadJson), &audit) != nil || audit.QuiescenceProof == "" {
				t.Fatal("invalid immutable boundary audit")
			}
			expected := data.StopBoundaryAudit{PriorRunRevision: req.ExpectedRunRevision, RunID: runID, PlanID: req.PlanID, RequestID: req.RequestID, EndlySessionID: session.SessionID, EndlyOperationID: op.ID, QuiescenceProof: audit.QuiescenceProof}
			if err := data.MatchStopBoundaryAudit(*event.PayloadJson, expected); err != nil {
				t.Fatal(err)
			}
		}
		if !found || committed.BoundaryID != data.StopBoundaryAuditID(p.Namespace, runID, req.RequestID) {
			t.Fatal("boundary audit identity missing")
		}
		if _, err := b.LoadResume(ctx, p, runID, committed.Run.Revision, state.PlanID, state.ObjectiveID); !errors.Is(err, ErrNeedsReconciliation) {
			t.Fatalf("unknown effect admitted resume: %v", err)
		}
	})
	if committed.Run == nil {
		t.Fatal("boundary did not return committed run")
	}
	t.Run("same request adopts without duplicate", func(t *testing.T) {
		beforeAdoption := read()
		adopted, err := b.StopBoundary(ctx, p, req)
		if err != nil || !adopted.CommitConfirmed || adopted.ResumeAdmitted || adopted.BoundaryID != committed.BoundaryID || adopted.Run == nil || adopted.Run.Revision != committed.Run.Revision {
			t.Fatalf("same request adoption: %+v %v", adopted, err)
		}
		if !reflect.DeepEqual(beforeAdoption, read()) {
			t.Fatal("adoption changed revision or audit")
		}
	})
	t.Run("different stale request rejects without mutation", func(t *testing.T) {
		stale := req
		stale.RequestID = "different-request"
		prior := read()
		result, err := b.StopBoundary(ctx, p, stale)
		if !errors.Is(err, ErrNeedsReconciliation) || result.CommitConfirmed {
			t.Fatalf("stale request adopted: %+v %v", result, err)
		}
		if !reflect.DeepEqual(prior, read()) {
			t.Fatal("stale request mutated durable run")
		}
	})
	t.Run("release failure retains committed boundary", func(t *testing.T) {
		next := req
		next.RequestID = "boundary-2"
		next.ExpectedRunRevision = committed.Run.Revision
		releaseErr = errors.New("fence cleanup failed")
		result, err := b.StopBoundary(ctx, p, next)
		if !errors.Is(err, releaseErr) || !result.CommitConfirmed || result.ResumeAdmitted || result.Run == nil || result.Run.Revision != next.ExpectedRunRevision+1 || !result.Run.NeedsAttention || result.Reason != "stopped-boundary guard cleanup unconfirmed" {
			t.Fatalf("cleanup lost commit result: %+v %v", result, err)
		}
		after := read()
		assertHistory(after, 2)
		if *after.Revision != next.ExpectedRunRevision+1 || *after.Status != "paused" {
			t.Fatal("cleanup failure rolled back committed boundary")
		}
		releaseErr = nil
	})
	if guardCalls != 5 || releases != 4 {
		t.Fatalf("guard lifecycle mismatch: calls=%d releases=%d", guardCalls, releases)
	}
}
