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

func TestNativeSelectionPreconditionGatesTextBeforeIntent(t *testing.T) {
	for _, mode := range []string{"true", "false", "wrong-type", "stale", "offline", "missing-evidence"} {
		t.Run(mode, func(t *testing.T) {
			_, file, _, _ := runtime.Caller(0)
			p, _ := auth.NewPrincipal("fixture", "", "precondition", []string{"desktop:control"})
			p.ClientID = "client"
			ctx := auth.WithPrincipal(context.Background(), p)
			var checks, calls atomic.Int32
			adapter, err := objective.NewNative(func(_ context.Context, actual auth.Principal, target model.Selector, attribute string) (model.Value, objective.NativeEvidence, error) {
				checks.Add(1)
				if actual.Namespace != p.Namespace || actual.ClientID != p.ClientID ||
					target.Surface.BundleID != "com.example.Editor" || target.Surface.ProcessID != 1 ||
					target.Surface.ProcessStartToken != "100:1" || target.Scope.Window["title"].String != "Fixture" ||
					target.Locator.Value.String != "editor" || attribute != "hasFullTextSelection" {
					t.Error("selection principal or target scope changed")
				}
				if mode == "offline" {
					return model.Value{}, objective.NativeEvidence{}, errors.New("unavailable")
				}
				value := model.Value{Kind: model.BoolValue, Bool: mode != "false"}
				if mode == "wrong-type" {
					value = model.Value{Kind: model.StringValue, String: "true"}
				}
				evidence := objective.NativeEvidence{HelperEpoch: "fixture", TargetRef: "editor", ObservedAt: time.Now()}
				if mode == "stale" {
					evidence.ObservedAt = time.Now().Add(-time.Hour)
				}
				if mode == "missing-evidence" {
					evidence.TargetRef = ""
				}
				return value, evidence, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			evaluator, err := objective.New(map[string]objective.Enrollment{"native": adapter.Enrollment()})
			if err != nil {
				t.Fatal(err)
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
			command := `app("com.example.Editor",processId:1,processStartToken:"100:1").typeWindowText(windowId:42,text:"Replacement",focusRole:"AXTextArea",focusName:"editor")`
			plan, err := script.Compile(command)
			if err != nil {
				t.Fatal(err)
			}
			plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: mode}}
			plan.Requires = &model.Requirements{Adapters: []string{"native"}}
			plan.Surfaces = map[string]model.Surface{"fixture": {Kind: "native", BundleID: "com.example.Editor", ProcessID: 1, ProcessStartToken: "100:1"}}
			inputs := map[string]model.Value{}
			for key, value := range map[string]string{"bundleID": "com.example.Editor", "processStartToken": "100:1", "windowTitle": "Fixture", "strategy": "id", "selector": "editor", "attribute": "hasFullTextSelection"} {
				inputs[key] = model.Value{Kind: model.StringValue, String: value}
			}
			inputs["processId"] = model.Value{Kind: model.NumberValue, Number: 1}
			inputs["expected"] = model.Value{Kind: model.BoolValue, Bool: true}
			plan.Steps[0].Precondition = &model.Predicate{Kind: "adapter", Adapter: "native", Name: "valueEquals", Inputs: inputs, Scope: model.PredicateScope{SurfaceRef: "fixture"}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "observational"}

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
			if checks.Load() != 1 {
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
