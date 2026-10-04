package host

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

func originalPostconditionContext() durable.ReconciliationContext {
	c := declaredContext()
	c.Step.Postcondition = c.Step.Effect.Reconcile
	c.Step.Effect.Reconcile = nil
	return c
}

func TestOriginalPostconditionPreservesSpecificEnrollmentAndFalseEvidence(t *testing.T) {
	ctx, p := reconciliationActor(t)
	c := originalPostconditionContext()
	legacy, err := nativeEffectReconciliationResolver([]string{nativeChromeExtensionsContract})(ctx, p, c)
	if err != nil || legacy.ID != nativeChromeExtensionsContract {
		t.Fatalf("existing contract disabled: %v", err)
	}
	contract, err := nativeEffectReconciliationResolver([]string{declaredPostconditionReconciliationContract})(ctx, p, c)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	adapter, _ := objective.NewNative(func(_ context.Context, _ auth.Principal, target model.Selector, attribute string) (model.Value, objective.NativeEvidence, error) {
		reads++
		if target.Surface != c.Step.Target.Surface {
			t.Fatal("read escaped original process")
		}
		return reconciliationString("not-ready"), objective.NativeEvidence{HelperEpoch: "fresh-epoch", TargetRef: "fresh-target", ObservedAt: time.Now()}, nil
	})
	evaluator, _ := objective.New(map[string]objective.Enrollment{"native": adapter.Enrollment()})
	result, err := evaluator.Evaluate(ctx, p, contract.Predicate, c.Values)
	if err != nil || result.Truth != objective.False || reads != 1 {
		t.Fatalf("false original condition promoted: %+v %v", result, err)
	}
}

func TestOriginalPostconditionContractIsDetachedAndScoped(t *testing.T) {
	ctx, p := reconciliationActor(t)
	c := originalPostconditionContext()
	before, _ := json.Marshal(c)
	resolver := nativeEffectReconciliationResolver([]string{declaredPostconditionReconciliationContract})
	contract, err := resolver(ctx, p, c)
	if err != nil || contract.ID != declaredPostconditionReconciliationContract {
		t.Fatalf("original predicate unavailable: %+v %v", contract, err)
	}
	contract.Predicate.Inputs["expected"] = reconciliationString("replacement")
	after, _ := json.Marshal(c)
	if string(before) != string(after) || c.Step.Effect.Reconcile != nil {
		t.Fatal("contract mutated original step or aliased its predicate")
	}
	for _, mutate := range []func(*durable.ReconciliationContext){
		func(c *durable.ReconciliationContext) { c.Step.Postcondition = nil },
		func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["processId"] = model.Value{Kind: model.NumberValue, Number: 9}
		},
		func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["processStartToken"] = reconciliationString("1:1")
		},
		func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["bundleID"] = reconciliationString("com.other.app")
		},
		func(c *durable.ReconciliationContext) { c.Step.Postcondition.Adapter = "caller-controlled" },
		func(c *durable.ReconciliationContext) { c.Step.Postcondition.Scope.SurfaceRef = "missing" },
	} {
		changed := originalPostconditionContext()
		mutate(&changed)
		if _, err := resolver(ctx, p, changed); err == nil {
			t.Fatal("missing or changed original scope accepted")
		}
	}
}

func TestOriginalPostconditionCannotBypassEffectDeclaration(t *testing.T) {
	ctx, p := reconciliationActor(t)
	c := originalPostconditionContext()
	if _, err := nativeEffectReconciliationResolver(nil)(ctx, p, c); err == nil {
		t.Fatal("unenrolled predicate accepted")
	}
	explicit := declaredContext().Step.Effect.Reconcile
	explicit.Inputs["expected"] = reconciliationString("explicit-effect")
	c.Step.Effect.Reconcile = explicit
	if _, err := nativeEffectReconciliationResolver([]string{declaredPostconditionReconciliationContract})(ctx, p, c); err == nil {
		t.Fatal("postcondition bypassed unenrolled explicit reconciliation")
	}
	contract, err := nativeEffectReconciliationResolver([]string{declaredPostconditionReconciliationContract, declaredEffectReconciliationContract})(ctx, p, c)
	if err != nil || contract.ID != declaredEffectReconciliationContract || contract.Predicate.Inputs["expected"].String != "explicit-effect" {
		t.Fatalf("effect declaration lost precedence: %+v %v", contract, err)
	}
}
