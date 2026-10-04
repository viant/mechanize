package durable

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/mechanize/script"
)

func TestFinalObjectivePreparationPrecedesFreshReceiptAndFailsBeforeOracle(t *testing.T) {
	clock := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	steps := []string{}
	result, err := evaluatePreparedObjective(context.Background(), func(context.Context) error {
		steps = append(steps, "prepare")
		clock = clock.Add(45 * time.Second) // Cold setup exceeds the unchanged 30s freshness window.
		return nil
	}, func(context.Context) (objective.Result, error) {
		steps = append(steps, "observe")
		return objective.Result{ObservedAt: clock}, nil
	})
	if err != nil || !reflect.DeepEqual(steps, []string{"prepare", "observe"}) || clock.Sub(result.ObservedAt) != 0 {
		t.Fatal("preparation consumed the fresh receipt window")
	}
	for _, mode := range []string{"prepare error", "cancelled before", "cancelled during"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled before" {
				cancel()
			}
			prepares, reads := 0, 0
			failure := errors.New("fixture metadata unavailable")
			_, err := evaluatePreparedObjective(ctx, func(context.Context) error {
				prepares++
				if mode == "prepare error" {
					return failure
				}
				cancel()
				return nil
			}, func(context.Context) (objective.Result, error) { reads++; return objective.Result{}, nil })
			if err == nil || !errors.Is(err, errObjectiveTransitionPreparation) || reads != 0 || mode == "cancelled before" && prepares != 0 {
				t.Fatal("failed preparation reached oracle")
			}
			if mode == "prepare error" && !errors.Is(err, failure) || mode != "prepare error" && !errors.Is(err, context.Canceled) {
				t.Fatal("preparation error lost")
			}
		})
	}
}

// No writer warming or setup completion is performed. The actual generated
// TransitionRun materialization must precede this independent oracle timestamp.
func TestColdGeneratedObjectiveFinalizationFreshAndStaleReceipts(t *testing.T) {
	for _, stale := range []bool{false, true} {
		name := "fresh"
		if stale {
			name = "stale"
		}
		t.Run(name, func(t *testing.T) {
			_, file, _, _ := runtime.Caller(0)
			p, _ := auth.NewPrincipal("fixture", "", "cold-objective", []string{"desktop:control"})
			ctx := auth.WithPrincipal(context.Background(), p)
			var reads, dispatches atomic.Int32
			var oracleAt atomic.Int64
			adapter := completionAdapterFunc(func(ctx context.Context, p auth.Principal, _ string, inputs map[string]model.Value) (objective.Result, error) {
				if err := ctx.Err(); err != nil {
					return objective.Result{}, err
				}
				reads.Add(1)
				observedAt := time.Now()
				oracleAt.Store(observedAt.UnixNano())
				if stale {
					observedAt = observedAt.Add(-time.Minute)
				}
				return objective.Result{Truth: objective.True, Authority: objective.Authoritative, ObservedAt: observedAt, Evidence: []objective.Evidence{{Kind: "independentReceipt", Reference: "fixture:receipt", BusinessKey: inputs["businessKey"].String}}}, nil
			})
			evaluator, _ := objective.New(map[string]objective.Enrollment{"fixture": {Adapter: adapter, MaximumAuthority: objective.Authoritative, AllowedPredicates: map[string]bool{"completed": true}}})
			var r *integration.Runtime
			b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), ObjectiveEvaluator: evaluator, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 0, nil }, StateMutationGuard: func(ctx context.Context, p auth.Principal, id string) (func(), error) {
				return r.StateMutationGuard(ctx, p, id)
			}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
				dispatches.Add(1)
				return integration.StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close(ctx)
			var completionStarted atomic.Int64
			r, err = integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, CompleteObjective: func(ctx context.Context, p auth.Principal, request integration.CompletionRequest) (integration.BusinessResult, error) {
				completionStarted.Store(time.Now().UnixNano())
				return b.CompleteObjective(ctx, p, request)
			}})
			if err != nil {
				t.Fatal(err)
			}
			session, err := r.Open(ctx, "cold objective fixture")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(ctx, session.SessionID)
			plan, err := script.Compile(`app("com.example.Fixture").getById("status").read("value")`)
			if err != nil {
				t.Fatal(err)
			}
			plan.Steps[0].TimeoutMs = 120000 // Isolated cold metadata budget; no native input is performed.
			plan.Surfaces = map[string]model.Surface{"fixture": plan.Steps[0].Target.Surface}
			plan.Requires = &model.Requirements{Adapters: []string{"fixture"}}
			plan.Objective = &model.Predicate{Kind: "adapter", Adapter: "fixture", Name: "completed", Scope: model.PredicateScope{SurfaceRef: "fixture"}, Inputs: map[string]model.Value{"businessKey": {Kind: model.StringValue, String: "case-1"}}, TimeoutMs: 30000, FreshnessMs: 30000, RequiredAuthority: "authoritative"}
			wait, cancel := context.WithTimeout(ctx, 120*time.Second)
			defer cancel()
			op, err := r.StartPlan(wait, session.SessionID, *plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Wait(wait, session.SessionID, op.ID); err != nil {
				t.Fatal(err)
			}
			result, err := r.Result(ctx, session.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			runID, err := r.RunReference(ctx, session.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			state, err := b.StateGet(ctx, p, runID)
			if err != nil {
				t.Fatal(err)
			}
			if reads.Load() != 1 || dispatches.Load() != 1 {
				t.Fatal("finalization repeated oracle or UI execution")
			}
			if stale {
				if result.BusinessStatus != "unverified" || result.VerificationState != "unknown" || state.Status != "paused" {
					t.Fatalf("genuine stale receipt promoted: %+v %+v", result, state)
				}
			} else if result.BusinessStatus != "succeeded" || result.VerificationState != "verified" || result.Objective == nil || state.Status != "succeeded" || objective.RequireBusinessSuccess(*result.Objective) != nil {
				t.Fatalf("cold fresh receipt lost: %+v %+v", result, state)
			}
			t.Logf("cold completion entry to oracle=%s; oracle to final readback=%s", time.Duration(oracleAt.Load()-completionStarted.Load()), time.Since(time.Unix(0, oracleAt.Load())))
		})
	}
}
