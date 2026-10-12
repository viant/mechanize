package durable

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestDynamicNativeOutcomeRootRefusedBeforeIntentAndDispatch(t *testing.T) {
	runNativeOutcomeAdmissionCase(t, "focusedElement", false)
}

func TestTrustedOutcomeAdmissionRefusedBeforeIntentAndDispatch(t *testing.T) {
	runNativeOutcomeAdmissionCase(t, "menuBar", true)
}

func runNativeOutcomeAdmissionCase(t *testing.T, root string, hostGuard bool) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture", "", "native-root-admission", []string{"desktop:control"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	var calls, admissions atomic.Int32
	options := Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}
	if hostGuard {
		options.ValidateStepOutcome = func(_ context.Context, actor auth.Principal, c ReconciliationContext) error {
			admissions.Add(1)
			if actor.Namespace != p.Namespace || c.Step.Target.Scope.NativeRoot != "menuBar" || len(c.Plan.Steps) != 1 || c.Values["input.root"].String != root {
				t.Error("admission lost immutable owned context")
			}
			return errors.New("fixture outcome contract refused")
		}
	}
	b, err := New(options, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
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
	session, err := rt.Open(ctx, "native outcome admission fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx, session.SessionID)
	plan, err := script.Compile(`app("fixture.app",processId:1,processStartToken:"100:1").menuBar().getById("open-recent").click()`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Requires = &model.Requirements{Adapters: []string{"native"}}
	plan.Inputs = map[string]model.InputDefinition{"root": {Type: model.StringValue}}
	plan.Surfaces = map[string]model.Surface{"fixture": plan.Steps[0].Target.Surface}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: "root-admission"}}
	plan.Steps[0].Postcondition = &model.Predicate{Kind: "adapter", Adapter: "native", Name: "valueEquals", Scope: model.PredicateScope{SurfaceRef: "fixture"}, Inputs: map[string]model.Value{"nativeRoot": {Kind: model.ReferenceValue, Ref: "input.root"}}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "observational"}
	op, err := rt.StartPlan(ctx, session.SessionID, *plan, map[string]model.Value{"root": {Kind: model.StringValue, String: root}})
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result, err := rt.Wait(wait, session.SessionID, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if hostGuard && admissions.Load() != 1 {
		t.Fatal("trusted outcome admission was not called exactly once")
	}
	if calls.Load() != 0 || result.Status != manager.OperationFailed {
		t.Fatalf("cross-root action dispatched: calls=%d status=%s", calls.Load(), result.Status)
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
	if len(saved.Attempts) != 0 || len(saved.Effects) != 0 {
		t.Fatal("rejected outcome committed an input intent")
	}
}
