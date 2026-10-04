package host

import (
	"context"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

func TestFocusReconciliationRequiresExactOriginalFocusAndBooleanEvidence(t *testing.T) {
	ctx, p := reconciliationActor(t)
	c := extensionsContext()
	c.Step.Action = "element.focus"
	c.Step.Target.Locator.Value = reconciliationString("checkbox")
	name := reconciliationString("Developer mode")
	c.Step.Target.Locator.Name = &name
	c.Step.Target.Scope.Window = map[string]model.Value{"title": reconciliationString("Extensions - Google Chrome")}
	resolver := nativeEffectReconciliationResolver([]string{nativeFocusContract})
	contract, err := resolver(ctx, p, c)
	if err != nil {
		t.Fatal(err)
	}
	if contract.Predicate.Inputs["expected"].Kind != model.BoolValue || !contract.Predicate.Inputs["expected"].Bool || contract.Predicate.Inputs["attribute"].String != "focused" {
		t.Fatal("focus contract invented a different condition")
	}
	value := model.Value{Kind: model.BoolValue, Bool: true}
	adapter, _ := objective.NewNative(func(_ context.Context, _ auth.Principal, target model.Selector, attribute string) (model.Value, objective.NativeEvidence, error) {
		if target.Surface != c.Step.Target.Surface || target.Locator.Name.String != "Developer mode" || target.Scope.Window["title"].String != "Extensions - Google Chrome" || attribute != "focused" {
			t.Fatal("focus read changed original target")
		}
		return value, objective.NativeEvidence{HelperEpoch: "fresh", TargetRef: "focused-target", ObservedAt: time.Now()}, nil
	})
	evaluator, _ := objective.New(map[string]objective.Enrollment{"native": adapter.Enrollment()})
	for _, test := range []struct {
		value model.Value
		want  objective.Truth
	}{{model.Value{Kind: model.BoolValue, Bool: true}, objective.True}, {model.Value{Kind: model.BoolValue, Bool: false}, objective.False}, {model.Value{Kind: model.StringValue, String: "true"}, objective.Unknown}} {
		value = test.value
		result, err := evaluator.Evaluate(ctx, p, contract.Predicate, nil)
		if err != nil || result.Truth != test.want {
			t.Fatalf("focus type proof: %+v %v", result, err)
		}
		if objective.RequireBusinessSuccess(result) == nil {
			t.Fatal("UI focus claimed business success")
		}
	}
	if _, err = nativeEffectReconciliationResolver(nil)(ctx, p, c); err == nil {
		t.Fatal("unenrolled focus adoption accepted")
	}
	c.Step.Action = "element.press"
	if _, err = resolver(ctx, p, c); err == nil {
		t.Fatal("focus contract adopted a press")
	}
}
