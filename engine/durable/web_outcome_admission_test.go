package durable

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/mechanize/script"
)

func TestWebOutcomeContractRejectedBeforeIntentAndValidReadWorks(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture", "", "web-contract", []string{"desktop:control", "desktop:observe"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	var dispatches, prepares, authorities atomic.Int32
	identity := objective.WebIdentity{ProfileChannel: "profile", BrowserInstance: "browser", Origin: "https://fixture.test", TabID: 7, FrameID: 0, DocumentID: "document", Generation: 1, ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: "scope"}
	adapter, e := objective.NewWebWithOptions(objective.WebOptions{ResolveIdentity: func(context.Context, auth.Principal, string) (objective.WebIdentity, error) { return identity, nil }, Read: func(_ context.Context, _ auth.Principal, selector model.Selector, _ string, _ objective.WebIdentity) (model.Value, objective.WebEvidence, error) {
		value := "ready"
		if selector.Locator.Value.String == "opened-tab" {
			value = "7"
		}
		return model.Value{Kind: model.StringValue, String: value}, objective.WebEvidence{Owner: p.Namespace, ClientID: p.ClientID, Identity: identity, RequestID: "fixture-request", ObservedAt: time.Now()}, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	evaluator, e := objective.New(map[string]objective.Enrollment{"web": adapter.Enrollment()})
	if e != nil {
		t.Fatal(e)
	}
	b, e := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), ObjectiveEvaluator: evaluator, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { authorities.Add(1); return 1, nil }}, func(_ context.Context, _ auth.Principal, step model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		dispatches.Add(1)
		result := integration.StepResult{DispatchState: "dispatched", VerificationState: "unverified"}
		if step.Action == "element.read" {
			result.Value = &model.Value{Kind: model.StringValue, String: "ready"}
		}
		if step.Action == "browser.openOrigin" {
			result.Value = &model.Value{Kind: model.StringValue, String: "7"}
		}
		return result, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close(ctx)
	rt, e := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: func(c context.Context, a auth.Principal, run, session string, plan model.Plan, inputs map[string]model.Value) (string, error) {
		prepares.Add(1)
		return b.PreparePlan(c, a, run, session, plan, inputs)
	}, AttachInitialOperation: func(c context.Context, a auth.Principal, run string, rev int, session, op string) error {
		_, e := b.AttachOperation(c, a, run, rev, session, op)
		return e
	}, EvaluatePostcondition: evaluator.Evaluate})
	if e != nil {
		t.Fatal(e)
	}
	session, e := rt.Open(ctx, "public contract fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer rt.Close(ctx, session.SessionID)
	for _, mode := range []string{"id", "authority", "resolved-invalid", "valid", "own-read", "own-open", "own-and-invalid-earlier", "own-and-missing-earlier", "own-precondition", "own-invalid-static"} {
		t.Run(mode, func(t *testing.T) {
			source := `web.tab(origin:"https://fixture.test").getById("message",exact:true).fill("ready",timeout:3s)`
			if strings.HasPrefix(mode, "own-") {
				source = `let current = web.tab(origin:"https://fixture.test").getById("message",exact:true).read("value")`
			}
			if mode == "own-open" {
				source = `let current = web.tab(origin:"https://fixture.test").openOrigin()`
			}
			plan, e := script.Compile(source)
			if e != nil {
				t.Fatal(e)
			}
			plan.Requires = &model.Requirements{Adapters: []string{"web"}}
			plan.Surfaces = map[string]model.Surface{"fixture": plan.Steps[0].Target.Surface}
			plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: mode}}
			inputs := map[string]model.Value{}
			for k, v := range map[string]string{"origin": "https://fixture.test", "strategy": "id", "selector": "message", "attribute": "value", "expected": "ready"} {
				inputs[k] = model.Value{Kind: model.StringValue, String: v}
			}
			pred := &model.Predicate{Kind: "adapter", Adapter: "web", Name: "valueEquals", Scope: model.PredicateScope{SurfaceRef: "fixture"}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "observational", Inputs: inputs}
			plan.Steps[0].Postcondition = pred
			variables := map[string]model.Value{}
			if strings.HasPrefix(mode, "own-") {
				inputs["expected"] = model.Value{Kind: model.ReferenceValue, Ref: "binding.current", Expected: model.StringValue}
			}
			if mode == "own-open" {
				inputs["selector"] = model.Value{Kind: model.StringValue, String: "opened-tab"}
			}
			if mode == "own-and-missing-earlier" {
				inputs["strategy"] = model.Value{Kind: model.ReferenceValue, Ref: "binding.missing", Expected: model.StringValue}
			}
			if mode == "own-precondition" {
				plan.Steps[0].Precondition = pred
				plan.Steps[0].Postcondition = nil
			}
			if mode == "own-invalid-static" {
				inputs["id"] = model.Value{Kind: model.StringValue, String: "message"}
			}
			if mode == "id" {
				delete(inputs, "strategy")
				delete(inputs, "selector")
				inputs["id"] = model.Value{Kind: model.StringValue, String: "message"}
			}
			if mode == "authority" {
				pred.RequiredAuthority = "authoritative"
			}
			if mode == "resolved-invalid" || mode == "own-and-invalid-earlier" {
				plan.Inputs = map[string]model.InputDefinition{"strategy": {Type: model.StringValue, Required: true}}
				inputs["strategy"] = model.Value{Kind: model.ReferenceValue, Ref: "input.strategy"}
				variables["strategy"] = model.Value{Kind: model.StringValue, String: "css"}
			}
			beforeDispatch, beforePrepare, beforeAuthority := dispatches.Load(), prepares.Load(), authorities.Load()
			op, e := rt.StartPlan(ctx, session.SessionID, *plan, variables)
			if mode == "id" || mode == "authority" || mode == "own-invalid-static" {
				var typed *model.MechanizeError
				if !errors.As(e, &typed) || typed.Code != "invalidPredicate" || typed.DispatchState != "notDispatched" || op != nil || prepares.Load() != beforePrepare || dispatches.Load() != beforeDispatch || authorities.Load() != beforeAuthority {
					t.Fatal("invalid contract reached durable preparation or input", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			wait, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			result, e := rt.Wait(wait, session.SessionID, op.ID)
			if e != nil {
				t.Fatal(e)
			}
			run, e := rt.RunReference(ctx, session.SessionID, op.ID)
			if e != nil {
				t.Fatal(e)
			}
			bound, user, e := b.bound(ctx, p, 1)
			if e != nil {
				t.Fatal(e)
			}
			saved, e := load(bound, user.server, p, run)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "resolved-invalid" || mode == "own-and-invalid-earlier" || mode == "own-and-missing-earlier" || mode == "own-precondition" {
				failure, e := rt.ExecutionFailure(ctx, session.SessionID, op.ID)
				if e != nil || failure == nil || failure.Code != "invalidPredicate" || failure.DispatchState != "notDispatched" || len(saved.Attempts) != 0 || len(saved.Effects) != 0 || dispatches.Load() != beforeDispatch || authorities.Load() != beforeAuthority {
					t.Fatal("resolved invalid contract minted authority intent or UNKNOWN", e)
				}
				return
			}
			wantEffects := 1
			if mode == "own-read" {
				wantEffects = 0
			}
			if result.Status != manager.OperationSucceeded || dispatches.Load() != beforeDispatch+1 || len(saved.Attempts) != wantEffects || len(saved.Effects) != wantEffects {
				t.Fatal("valid observational contract did not execute once and verify", result.Status)
			}
		})
	}
}
