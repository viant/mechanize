package durable

import (
	"context"
	"errors"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestDurablePreconditionGatesInputBeforeIntent(t *testing.T) {
	for _, mode := range []string{"true", "false", "unknown", "stale", "offline", "missing", "read-false"} {
		t.Run(mode, func(t *testing.T) {
			_, file, _, _ := runtime.Caller(0)
			p, _ := auth.NewPrincipal("fixture", "", "precondition", []string{"desktop:control"})
			p.ClientID = "client"
			ctx := auth.WithPrincipal(context.Background(), p)
			var checks, calls atomic.Int32
			evaluator, err := objective.New(map[string]objective.Enrollment{"baseline": {MaximumAuthority: objective.Observational, AllowedPredicates: map[string]bool{"empty": true}, Adapter: completionAdapterFunc(func(c context.Context, actual auth.Principal, _ string, _ map[string]model.Value) (objective.Result, error) {
				checks.Add(1)
				if actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
					t.Error("baseline principal changed")
				}
				if mode == "offline" {
					return objective.Result{}, errors.New("unavailable")
				}
				result := objective.Result{Truth: objective.True, Authority: objective.Observational, ObservedAt: time.Now(), Evidence: []objective.Evidence{{Kind: "fixture", Reference: "blank-editor"}}}
				if mode == "false" || mode == "read-false" {
					result.Truth = objective.False
				}
				if mode == "unknown" {
					result.Truth = objective.Unknown
				}
				if mode == "stale" {
					result.ObservedAt = time.Now().Add(-time.Hour)
				}
				return result, nil
			})}})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing" {
				evaluator = nil
			}
			b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), ObjectiveEvaluator: evaluator, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
				calls.Add(1)
				return integration.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close(ctx)
			rt, err := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, AttachInitialOperation: func(c context.Context, p auth.Principal, run string, rev int, session, op string) error {
				_, err := b.AttachOperation(c, p, run, rev, session, op)
				return err
			}})
			if err != nil {
				t.Fatal(err)
			}
			session, err := rt.Open(ctx, "precondition fixture")
			if err != nil {
				t.Fatal(err)
			}
			defer rt.Close(ctx, session.SessionID)
			command := `app("fixture.app").getById("save").click()`
			if mode == "read-false" {
				command = `app("fixture.app").getById("save").read("name")`
			}
			plan, err := script.Compile(command)
			if err != nil {
				t.Fatal(err)
			}
			plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: mode}}
			plan.Requires = &model.Requirements{Adapters: []string{"baseline"}}
			plan.Surfaces = map[string]model.Surface{"fixture": {Kind: "native", BundleID: "fixture.app"}}
			plan.Steps[0].Precondition = &model.Predicate{Kind: "adapter", Adapter: "baseline", Name: "empty", Scope: model.PredicateScope{SurfaceRef: "fixture"}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "observational"}
			op, err := rt.StartPlan(ctx, session.SessionID, *plan, nil)
			if err != nil {
				t.Fatal(err)
			}
			wait, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			result, err := rt.Wait(wait, session.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			want := int32(0)
			if mode == "true" {
				want = 1
			}
			if calls.Load() != want || (result.Status == manager.OperationSucceeded) != (mode == "true") {
				t.Fatalf("mode=%s calls=%d status=%s result=%+v", mode, calls.Load(), result.Status, result)
			}
			if mode != "missing" && checks.Load() != 1 {
				t.Fatalf("expected one baseline check, got %d", checks.Load())
			}
			run, err := rt.RunReference(ctx, session.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			bounded, user, err := b.bound(ctx, p, 1)
			if err != nil {
				t.Fatal(err)
			}
			saved, err := load(bounded, user.server, p, run)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "true" && (len(saved.Attempts) != 0 || len(saved.Effects) != 0) {
				t.Fatal("failed baseline committed an input intent")
			}
		})
	}
}
