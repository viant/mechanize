package durable

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/mechanize/objective/fixture"
	"github.com/viant/mechanize/script"
)

func TestDispatchedActionsContinueAndResumeWithoutBusinessVerification(t *testing.T) {
	for _, mode := range []string{"sequence", "restart", "unknown", "cleanup", "objective-false"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := auth.NewPrincipal("fixture", "", "dispatch-completion", []string{"desktop:control"})
			p.ClientID = "fixture-client"
			ctx := auth.WithPrincipal(context.Background(), p)
			oracle := fixture.New()
			evaluator, e := objective.New(map[string]objective.Enrollment{"fixture-receipts": oracle.Enrollment()})
			if e != nil {
				t.Fatal(e)
			}
			var mu sync.Mutex
			calls := map[string]int{}
			captured := map[string]context.Context{}
			stopped := mode == "restart"
			dispatch := func(c context.Context, _ auth.Principal, s model.Step, _ map[string]model.Value) (integration.StepResult, error) {
				mu.Lock()
				defer mu.Unlock()
				calls[s.ID]++
				captured[s.ID] = c
				if s.ID == "second" && stopped {
					return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, errors.New("fixture interrupted before second action")
				}
				if s.ID == "first" && mode == "unknown" {
					return integration.StepResult{DispatchState: "unknown", VerificationState: "unknown"}, errors.New("fixture missing receipt")
				}
				if s.ID == "first" && mode == "cleanup" {
					return integration.StepResult{DispatchState: "dispatched", VerificationState: "unknown"}, errors.New("fixture cleanup unconfirmed")
				}
				if s.ID == "second" {
					oracle.Put(p, fixture.Receipt{Reference: "fixture:receipt", BusinessKey: "public-case", Completed: false, ObservedAt: time.Now()})
				}
				return integration.StepResult{DispatchState: "dispatched", VerificationState: "unknown"}, nil
			}
			opts := Options{ObjectiveEvaluator: evaluator, SourceRoot: filepath.Join(t.TempDir(), "missing-source"), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}
			b, e := New(opts, dispatch)
			if e != nil {
				t.Fatal(e)
			}
			makeRuntime := func() *integration.Runtime {
				r, e := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, CompleteObjective: b.CompleteObjective, LoadResume: b.LoadResume, AttachInitialOperation: func(c context.Context, a auth.Principal, run string, revision int, session, op string) error {
					_, e := b.AttachOperation(c, a, run, revision, session, op)
					return e
				}, AttachOperation: func(c context.Context, a auth.Principal, run string, revision int, session, op string) error {
					_, e := b.AttachResumedOperation(c, a, run, revision, session, op)
					return e
				}})
				if e != nil {
					t.Fatal(e)
				}
				b.options.StateMutationGuard = r.StateMutationGuard
				return r
			}
			r := makeRuntime()
			session, e := r.Open(ctx, "public fixture sequence")
			if e != nil {
				t.Fatal(e)
			}
			plan, e := script.Compile("web.tab(origin:\"https://fixture.test\").getById(\"message\",exact:true).fill(\"hello\")\nweb.tab(origin:\"https://fixture.test\").getById(\"apply\",exact:true).click()")
			if e != nil {
				t.Fatal(e)
			}
			for i, id := range []string{"first", "second"} {
				plan.Steps[i].ID = id
				plan.Steps[i].Effect.BusinessKey = map[string]model.Value{"step": {Kind: model.StringValue, String: id}}
			}
			if mode == "objective-false" {
				plan.Requires = &model.Requirements{Adapters: []string{"fixture-receipts"}}
				plan.Surfaces = map[string]model.Surface{"fixture": plan.Steps[0].Target.Surface}
				plan.Objective = &model.Predicate{Kind: "adapter", Adapter: "fixture-receipts", Name: "receiptCompleted", Scope: model.PredicateScope{SurfaceRef: "fixture"}, Inputs: map[string]model.Value{"businessKey": {Kind: model.StringValue, String: "public-case"}}, TimeoutMs: 30000, FreshnessMs: 30000, RequiredAuthority: "authoritative"}
			}
			op, e := r.StartPlanWithRequest(ctx, session.SessionID, "original-request", *plan, nil)
			if e != nil {
				t.Fatal(e)
			}
			wait, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			done, e := r.Wait(wait, session.SessionID, op.ID)
			if e != nil {
				t.Fatal(e)
			}
			replay, e := r.StartPlanWithRequest(ctx, session.SessionID, "original-request", *plan, nil)
			if e != nil || replay.ID != op.ID {
				t.Fatal("same request did not return original operation", e)
			}
			run, e := r.RunReference(ctx, session.SessionID, op.ID)
			if e != nil {
				t.Fatal(e)
			}
			state, e := b.StateGet(ctx, p, run)
			if e != nil {
				t.Fatal(e)
			}
			business, e := r.Result(ctx, session.SessionID, op.ID)
			wantBusiness := "unverified"
			if mode == "objective-false" {
				wantBusiness = "failed"
			}
			if e != nil || business.BusinessStatus != wantBusiness {
				t.Fatal("invented business success", e)
			}
			if mode == "unknown" || mode == "cleanup" {
				if done.Status != "failed" || len(state.UnresolvedEffects) != 1 || calls["second"] != 0 {
					t.Fatal("uncertain input admitted continuation")
				}
				if _, e = b.LoadResume(ctx, p, run, state.Revision, state.PlanID, state.ObjectiveID); !errors.Is(e, ErrNeedsReconciliation) {
					t.Fatal("uncertain history resumed", e)
				}
			} else {
				if len(state.Progress) != 0 || len(state.UnresolvedEffects) != 0 {
					t.Fatal("plain dispatch made a milestone or UNKNOWN")
				}
				if mode == "sequence" && (done.Status != "succeeded" || business.VerificationState != "unverified" || calls["second"] != 1) {
					t.Fatal("plain sequence failed", done.Error, business)
				}
				if mode == "objective-false" && (done.Status != "succeeded" || business.VerificationState != "verified" || state.Status != "failed") {
					t.Fatal("unsatisfied objective was promoted or action completion failed", business, state.Status)
				}
				if mode == "restart" && done.Status != "failed" {
					t.Fatal("interrupted action not stopped")
				}
			}
			loadEvidence := func() map[string]string {
				c, u, e := b.bound(ctx, p, 0)
				if e != nil {
					t.Fatal(e)
				}
				loaded, e := load(c, u.server, p, run)
				if e != nil {
					t.Fatal(e)
				}
				out := map[string]string{}
				for _, effect := range loaded.Effects {
					if effect.State != nil && *effect.State == "dispatched" {
						var proof integration.StepResult
						if effect.EvidenceJson == nil || json.Unmarshal([]byte(*effect.EvidenceJson), &proof) != nil || !proof.DispatchedUnverified() {
							t.Fatal("invalid dispatched evidence")
						}
						out[*effect.AttemptId] = *effect.EvidenceJson
					}
				}
				return out
			}
			original := loadEvidence()
			r.Close(ctx, session.SessionID)
			if e = b.Close(ctx); e != nil {
				t.Fatal(e)
			}
			b, e = New(opts, dispatch)
			if e != nil {
				t.Fatal(e)
			}
			defer b.Close(ctx)
			before := calls["first"]
			receipt, e := b.Execute(context.WithoutCancel(captured["first"]), p, plan.Steps[0], nil)
			if mode == "unknown" || mode == "cleanup" {
				if !errors.Is(e, ErrNeedsReconciliation) {
					t.Fatal("unknown restarted replay accepted", e)
				}
			} else if e != nil || !receipt.DispatchedUnverified() {
				t.Fatal("restart lost original receipt", e)
			}
			if calls["first"] != before {
				t.Fatal("restart repeated dispatched input")
			}
			if mode == "restart" {
				stopped = false
				r = makeRuntime()
				resumed, e := r.Resume(ctx, p, run, state.Revision, state.PlanID, state.ObjectiveID)
				if e != nil {
					t.Fatal(e)
				}
				finished, e := r.Wait(wait, resumed.SessionID, resumed.Operation.ID)
				if e != nil || finished.Status != "succeeded" {
					t.Fatal("resume failed", e, finished)
				}
				if calls["first"] != 1 || calls["second"] != 2 {
					t.Fatal("resume duplicated first action", calls)
				}
				now := loadEvidence()
				for k, v := range original {
					if now[k] != v {
						t.Fatal("resume rewrote original receipt")
					}
				}
				r.Close(ctx, resumed.SessionID)
			}
		})
	}
}
