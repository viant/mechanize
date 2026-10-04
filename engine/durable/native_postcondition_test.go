package durable

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/mechanize/script"
)

func TestGeneratedNativePostconditionPromotesOnlyFreshIndependentEvidence(t *testing.T) {
	for _, mode := range []string{"receipt-only", "fresh-true", "false", "stale", "unavailable", "missing-evidence"} {
		t.Run(mode, func(t *testing.T) {
			_, file, _, _ := runtime.Caller(0)
			p, _ := auth.NewPrincipal("fixture:issuer", "", "native-effect-"+mode, []string{"desktop:control"})
			ctx := auth.WithPrincipal(context.Background(), p)
			adapter, _ := objective.NewNative(func(_ context.Context, _ auth.Principal, target model.Selector, attribute string) (model.Value, objective.NativeEvidence, error) {
				if target.Surface.BundleID != "com.example.Fixture" || target.Locator.Value.String != "display" || attribute != "value" {
					t.Fatal("postcondition target changed")
				}
				if mode == "unavailable" {
					return model.Value{}, objective.NativeEvidence{}, errors.New("fixture source unavailable")
				}
				value := "42"
				if mode == "false" {
					value = "41"
				}
				observed := time.Now()
				if mode == "stale" {
					observed = observed.Add(-time.Hour)
				}
				ref := "read-ref"
				if mode == "missing-evidence" {
					ref = ""
				}
				return model.Value{Kind: model.StringValue, String: value}, objective.NativeEvidence{HelperEpoch: "read-epoch", TargetRef: ref, ObservedAt: observed}, nil
			})
			evaluator, err := objective.New(map[string]objective.Enrollment{"native": adapter.Enrollment()})
			if err != nil {
				t.Fatal(err)
			}
			dispatches := 0
			var captured context.Context
			builder, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), ObjectiveEvaluator: evaluator, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(c context.Context, _ auth.Principal, _ model.Step, _ map[string]model.Value) (integration.StepResult, error) {
				dispatches++
				captured = c
				return integration.StepResult{DispatchState: "dispatched", VerificationState: "unknown"}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer builder.Close(ctx)
			orchestrator, err := integration.NewWithOptions(builder.Execute, integration.Options{PreparePlan: builder.PreparePlan, EvaluatePostcondition: builder.EvaluatePostcondition, CompleteObjective: builder.CompleteObjective, AttachInitialOperation: func(ctx context.Context, p auth.Principal, runID string, revision int, sessionID, operationID string) error {
				_, err := builder.AttachOperation(ctx, p, runID, revision, sessionID, operationID)
				return err
			}})
			if err != nil {
				t.Fatal(err)
			}
			session, err := orchestrator.Open(ctx, "native observation fixture")
			if err != nil {
				t.Fatal(err)
			}
			plan, err := script.Compile(`app("com.example.Fixture").getById("calculate").click()`)
			if err != nil {
				t.Fatal(err)
			}
			plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"fixtureCase": {Kind: model.StringValue, String: "case-1"}}
			if mode != "receipt-only" {
				plan.Requires = &model.Requirements{Adapters: []string{"native"}}
				plan.Surfaces = map[string]model.Surface{"fixture": {Kind: "native", BundleID: "com.example.Fixture"}}
				inputs := map[string]model.Value{}
				for name, value := range map[string]string{"bundleID": "com.example.Fixture", "strategy": "id", "selector": "display", "attribute": "value", "expected": "42"} {
					inputs[name] = model.Value{Kind: model.StringValue, String: value}
				}
				plan.Steps[0].Postcondition = &model.Predicate{Kind: "adapter", Adapter: "native", Name: "valueEquals", Inputs: inputs, Scope: model.PredicateScope{SurfaceRef: "fixture"}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "observational"}
			}
			op, err := orchestrator.StartPlan(ctx, session.SessionID, *plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			wait, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if _, err = orchestrator.Wait(wait, session.SessionID, op.ID); err != nil {
				t.Fatal(err)
			}
			runID, err := orchestrator.RunReference(ctx, session.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			bound, user, err := builder.bound(ctx, p, 0)
			if err != nil {
				t.Fatal(err)
			}
			persisted, err := load(bound, user.server, p, runID)
			if err != nil {
				t.Fatal(err)
			}
			if len(persisted.Effects) != 1 || persisted.Effects[0].State == nil || persisted.Effects[0].EvidenceJson == nil {
				t.Fatalf("durable effect missing %+v", persisted)
			}
			var result integration.StepResult
			if err = json.Unmarshal([]byte(*persisted.Effects[0].EvidenceJson), &result); err != nil {
				t.Fatal(err)
			}
			wantState, wantVerification := "unknown", "unknown"
			if mode == "fresh-true" {
				wantState, wantVerification = "confirmed", "verified"
			}
			if *persisted.Effects[0].State != wantState || result.VerificationState != wantVerification {
				t.Fatalf("state=%s evidence=%+v", *persisted.Effects[0].State, result)
			}
			if mode == "fresh-true" {
				if result.Postcondition == nil || result.Postcondition.Authority != objective.Observational || len(persisted.Milestones) != 1 {
					t.Fatalf("independent UI proof not committed %+v", result)
				}
			} else if len(persisted.Milestones) != 0 {
				t.Fatal("unverified effect gained a milestone")
			}
			business, err := orchestrator.Result(ctx, session.SessionID, op.ID)
			if err != nil || business.BusinessStatus == "succeeded" {
				t.Fatalf("UI evidence became business success %+v %v", business, err)
			}
			_, err = builder.Execute(context.WithoutCancel(captured), p, plan.Steps[0], nil)
			if mode == "fresh-true" {
				if err != nil {
					t.Fatalf("confirmed outcome not adopted: %v", err)
				}
			} else if !errors.Is(err, ErrNeedsReconciliation) {
				t.Fatalf("unknown barrier lost: %v", err)
			}
			if dispatches != 1 {
				t.Fatalf("effect replayed %d times", dispatches)
			}
		})
	}
}
