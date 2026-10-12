package host

import (
	"context"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestOwnerPauseWaitsForDurableCompletionAndResumesWithoutReplay(t *testing.T) {
	for _, mode := range []string{"pause", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			_, file, _, _ := runtime.Caller(0)
			p, _ := auth.NewPrincipal("fixture", "", "pause-owner", []string{"desktop:control"})
			p.ClientID = "client"
			ctx, cancel := context.WithTimeout(auth.WithPrincipal(context.Background(), p), 30*time.Second)
			defer cancel()
			entered := make(chan struct{})
			var first, second, stops atomic.Int32
			var rt *automation.Runtime
			b, err := durable.New(durable.Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, StateMutationGuard: func(c context.Context, p auth.Principal, run string) (func(), error) {
				return rt.StateMutationGuard(c, p, run)
			}}, func(c context.Context, _ auth.Principal, step model.Step, _ map[string]model.Value) (automation.StepResult, error) {
				if step.ID == "first" {
					first.Add(1)
					return automation.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
				}
				if second.Add(1) == 1 {
					close(entered)
					<-c.Done()
					stops.Add(1)
					return automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, c.Err()
				}
				return automation.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close(context.WithoutCancel(ctx))
			rt, err = automation.NewWithOptions(b.Execute, automation.Options{PreparePlan: b.PreparePlan, CompleteObjective: b.CompleteObjective, LoadResume: b.LoadResume, AttachInitialOperation: func(c context.Context, p auth.Principal, run string, rev int, session, op string) error {
				_, e := b.AttachOperation(c, p, run, rev, session, op)
				return e
			}, AttachOperation: func(c context.Context, p auth.Principal, run string, rev int, session, op string) error {
				_, e := b.AttachResumedOperation(c, p, run, rev, session, op)
				return e
			}})
			if err != nil {
				t.Fatal(err)
			}
			h := &Host{Runtime: rt, durable: b, users: map[string]User{p.Namespace: {}}}
			session, err := rt.Open(ctx, "pause fixture")
			if err != nil {
				t.Fatal(err)
			}
			defer rt.Close(context.WithoutCancel(ctx), session.SessionID)
			plan, err := script.Compile("app(\"fixture.app\").getById(\"first\").click()\napp(\"fixture.app\").getById(\"second\").click()")
			if err != nil {
				t.Fatal(err)
			}
			for i, id := range []string{"first", "second"} {
				plan.Steps[i].ID = id
				plan.Steps[i].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: id}}
			}
			op, err := rt.StartPlan(ctx, session.SessionID, *plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("executor never reached interruption point")
			}
			run, err := rt.RunReference(ctx, session.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			state, err := b.PauseReference(ctx, p, run)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "cancel" {
				if _, err = rt.Cancel(ctx, session.SessionID, op.ID); err != nil {
					t.Fatal(err)
				}
				if _, err = rt.Wait(ctx, session.SessionID, op.ID); err != nil {
					t.Fatal(err)
				}
				state, err = b.StateGet(ctx, p, run)
				if err != nil || state.Status != "cancelled" {
					t.Fatalf("explicit cancel lost terminality: %+v %v", state, err)
				}
				if _, err = h.PauseRun(ctx, p, run, state.Revision); err == nil {
					t.Fatal("terminal cancel converted to pause")
				}
				return
			}
			if _, err = h.PauseRun(ctx, p, run, state.Revision-1); err == nil || stops.Load() != 0 {
				t.Fatal("stale pause stopped executor")
			}
			paused, err := h.PauseRun(ctx, p, run, state.Revision)
			if err != nil || paused.Status != "paused" || paused.Revision <= state.Revision || len(paused.UnresolvedEffects) != 0 {
				t.Fatalf("pause did not adopt completed boundary: %+v %v", paused, err)
			}
			resumed, err := rt.ResumeInSession(ctx, p, session.SessionID, run, paused.Revision, paused.PlanID, paused.ObjectiveID)
			if err != nil {
				t.Fatal(err)
			}
			done, err := rt.Wait(ctx, session.SessionID, resumed.Operation.ID)
			if err != nil || done.Status != manager.OperationSucceeded || first.Load() != 1 || second.Load() != 2 {
				t.Fatalf("resume replayed prefix or failed: %+v %v first=%d second=%d", done, err, first.Load(), second.Load())
			}
		})
	}
}
