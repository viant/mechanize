package durable

import (
	"context"
	"encoding/json"
	"errors"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/beginattempt"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCommittedStepIntentBeginOutputRejectsContradictions(t *testing.T) {
	r := data.CommittedStepIntent{Namespace: "namespace", RunID: "run", PlanID: "plan", StepID: "step", AttemptID: "attempt", EffectID: "effect", LeaseEpoch: 7, SessionID: "session", OperationID: "operation"}
	complete := func() *beginattempt.BeginAttemptOutput {
		return &beginattempt.BeginAttemptOutput{Data: []*beginattempt.Run{{Namespace: pointer(r.Namespace), Id: pointer(r.RunID), Revision: pointer(2), Attempts: []*beginattempt.Attempt{{Namespace: pointer(r.Namespace), Id: pointer(r.AttemptID), RunId: pointer(r.RunID), PlanId: pointer(r.PlanID), StepId: pointer(r.StepID), LeaseEpoch: pointer(7), State: pointer("intent"), Intents: []*beginattempt.Intent{{Namespace: pointer(r.Namespace), Id: pointer(r.EffectID), AttemptId: pointer(r.AttemptID), RunId: pointer(r.RunID), State: pointer("intent"), Revision: pointer(1)}}}}}}}
	}
	for _, mode := range []string{"complete", "missing", "wrongRevision", "wrongRoot", "wrongAttempt", "wrongEffect", "wrongEpoch", "resolved", "wrongCorrelation"} {
		t.Run(mode, func(t *testing.T) {
			out := complete()
			switch mode {
			case "missing":
				out.Data[0].Revision = nil
			case "wrongRevision":
				out.Data[0].Revision = pointer(1)
			case "wrongRoot":
				out.Data[0].Id = pointer("foreign")
			case "wrongAttempt":
				out.Data[0].Attempts[0].Id = pointer("foreign")
			case "wrongEffect":
				out.Data[0].Attempts[0].Intents[0].Id = pointer("foreign")
			case "wrongEpoch":
				out.Data[0].Attempts[0].LeaseEpoch = pointer(8)
			case "resolved":
				out.Data[0].Attempts[0].Intents[0].State = pointer("confirmed")
			case "wrongCorrelation":
				out.Data[0].EndlyOperationId = pointer("foreign")
			}
			copy := r
			ok, e := committedIntentFromBegin(out, 1, &copy)
			if mode == "complete" {
				if !ok || e != nil || copy.RunRevision != 2 {
					t.Fatal("complete committed output rejected", ok, e)
				}
			} else if mode == "missing" {
				if ok || e != nil {
					t.Fatal("missing output cannot request fallback", ok, e)
				}
			} else if e == nil {
				t.Fatal("contradictory output permitted fallback", mode)
			}
		})
	}
}

func TestGeneratedCommittedStepIntentBaseResumeAndReadonly(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture", "", "committed-intent", []string{"desktop:control"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	var b *Builder
	var captured []context.Context
	var records []data.CommittedStepIntent
	readonlyCalls := 0
	dispatch := func(c context.Context, p auth.Principal, s model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		if s.Effect.Class == model.ReadOnly {
			readonlyCalls++
			if _, e := data.RequireCommittedStepIntent(c, p); e == nil {
				return integration.StepResult{}, errors.New("readonly received committed mutation context")
			}
			return integration.StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
		}
		record, e := data.RequireCommittedStepIntent(c, p)
		if e != nil {
			return integration.StepResult{}, e
		}
		meta, _ := integration.ExecutionFromContext(c)
		if record.Namespace != p.Namespace || record.ClientID != p.ClientID || record.RunID != meta.RunID || record.PlanID != meta.PlanID || record.StepID != s.ID || record.StepIndex != meta.StepIndex || record.SessionID != meta.SessionID || record.OperationID != meta.OperationID || record.LeaseEpoch != 7 {
			return integration.StepResult{}, errors.New("committed correlation lost")
		}
		persisted, e := load(c, b.users[p.Namespace].server, p, meta.RunID)
		if e != nil {
			return integration.StepResult{}, e
		}
		if persisted.Revision == nil || record.RunRevision != *persisted.Revision {
			return integration.StepResult{}, errors.New("revision guessed instead of committed")
		}
		want := key("attempt", meta.RunID, meta.PlanID, s.ID)
		if meta.Resumed {
			want = key("attempt-resume", meta.RunID, meta.PlanID, s.ID, meta.OperationID)
		}
		if record.AttemptID != want || record.EffectID != key("effect", want) {
			return integration.StepResult{}, errors.New("actual committed attempt identity lost")
		}
		captured = append(captured, c)
		records = append(records, record)
		if !meta.Resumed {
			return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, errors.New("fixture proven absent")
		}
		return integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
	}
	var e error
	b, e = New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 7, nil }}, dispatch)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close(ctx)
	rt, e := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, CompleteObjective: b.CompleteObjective, LoadResume: b.LoadResume, AttachInitialOperation: func(c context.Context, p auth.Principal, run string, rev int, session, op string) error {
		_, e := b.AttachOperation(c, p, run, rev, session, op)
		return e
	}, AttachOperation: func(c context.Context, p auth.Principal, run string, rev int, session, op string) error {
		_, e := b.AttachResumedOperation(c, p, run, rev, session, op)
		return e
	}})
	if e != nil {
		t.Fatal(e)
	}
	session, e := rt.Open(ctx, "committed intent fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer rt.Close(ctx, session.SessionID)
	plan, e := script.Compile(`app("fixture.app").getById("save").click()`)
	if e != nil {
		t.Fatal(e)
	}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: "fixture"}}
	wait, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	op, e := rt.StartPlan(ctx, session.SessionID, *plan, nil)
	if e != nil {
		t.Fatal(e)
	}
	finished, e := rt.Wait(wait, session.SessionID, op.ID)
	if e != nil || finished.Status != manager.OperationFailed || len(records) != 1 {
		t.Fatalf("baseline %+v %v records%d", finished, e, len(records))
	}
	if _, e = data.RequireCommittedStepIntent(context.WithoutCancel(captured[0]), p); e == nil {
		t.Fatal("callback proof survived dispatch return")
	}
	run, e := rt.RunReference(ctx, session.SessionID, op.ID)
	if e != nil {
		t.Fatal(e)
	}
	state, e := b.StateGet(ctx, p, run)
	if e != nil || len(state.UnresolvedEffects) != 0 {
		t.Fatal("absence not persisted", state, e)
	}
	resumed, e := rt.ResumeInSession(ctx, p, session.SessionID, run, state.Revision, state.PlanID, state.ObjectiveID)
	if e != nil {
		t.Fatal(e)
	}
	finished, e = rt.Wait(wait, session.SessionID, resumed.Operation.ID)
	if e != nil || finished.Status != manager.OperationSucceeded || len(records) != 2 {
		t.Fatalf("resumed %+v %v records%d", finished, e, len(records))
	}
	if records[0].AttemptID == records[1].AttemptID || records[0].OperationID == records[1].OperationID || records[1].RunRevision <= records[0].RunRevision {
		t.Fatal("resume adopted base identity")
	}
	if _, e = data.RequireCommittedStepIntent(context.WithoutCancel(captured[1]), p); e == nil {
		t.Fatal("resumed callback proof survived return")
	}
	readPlan, e := script.Compile(`app("fixture.app").getById("save").read("name")`)
	if e != nil {
		t.Fatal(e)
	}
	readOp, e := rt.StartPlan(ctx, session.SessionID, *readPlan, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = rt.Wait(wait, session.SessionID, readOp.ID); e != nil || readonlyCalls != 1 {
		t.Fatal("read-only path failed", e, readonlyCalls)
	}
}

func TestGeneratedCommittedStepIntentMintFailurePersistsAbsence(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture", "", "invalid-client-context", []string{"desktop:control"})
	p.ClientID = strings.Repeat("x", 257)
	ctx := auth.WithPrincipal(context.Background(), p)
	calls := 0
	b, e := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 7, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		calls++
		return integration.StepResult{}, errors.New("must not dispatch")
	})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close(ctx)
	rt, e := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan})
	if e != nil {
		t.Fatal(e)
	}
	session, e := rt.Open(ctx, "context failure fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer rt.Close(ctx, session.SessionID)
	plan, e := script.Compile(`app("fixture.app").getById("save").click()`)
	if e != nil {
		t.Fatal(e)
	}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: "fixture"}}
	op, e := rt.StartPlan(ctx, session.SessionID, *plan, nil)
	if e != nil {
		t.Fatal(e)
	}
	wait, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	finished, e := rt.Wait(wait, session.SessionID, op.ID)
	if e != nil || finished.Status != manager.OperationFailed || calls != 0 {
		t.Fatalf("context failure dispatched %+v %v calls%d", finished, e, calls)
	}
	runID, e := rt.RunReference(ctx, session.SessionID, op.ID)
	if e != nil {
		t.Fatal(e)
	}
	bound, user, e := b.bound(ctx, p, 7)
	if e != nil {
		t.Fatal(e)
	}
	user.mu.Lock()
	run, e := load(bound, user.server, p, runID)
	user.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if len(run.Attempts) != 1 || len(run.Effects) != 1 || run.Effects[0].State == nil || *run.Effects[0].State != "absent" {
		t.Fatalf("context failure left gratuitous unknown: %+v", run.Effects)
	}
	var evidence integration.StepResult
	if run.Effects[0].EvidenceJson == nil || json.Unmarshal([]byte(*run.Effects[0].EvidenceJson), &evidence) != nil || evidence.DispatchState != "notDispatched" {
		t.Fatal("absence lacks non-dispatch evidence")
	}
}
