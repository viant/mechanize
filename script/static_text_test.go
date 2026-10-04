package script

import (
	"testing"

	"github.com/viant/mechanize/model"
)

func TestNativeStaticTextReadWithWindowAncestorAndTypedBinding(t *testing.T) {
	plan, err := Compile(`let calc = app("com.apple.calculator").window(title: "Calculator")
let result = calc.getByRole("text").within(calc.getById("StandardResultView")).read("staticText")`)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 1 {
		t.Fatalf("steps: %+v", plan.Steps)
	}
	step := plan.Steps[0]
	if step.Action != "element.read" || step.Arguments["attribute"].String != "staticText" || step.ResultType != model.StringValue || step.Effect.Class != model.ReadOnly || step.Target.Ancestor == nil || step.Target.Ancestor.Locator.Value.String != "StandardResultView" || step.Target.Scope.Window["title"].String != "Calculator" {
		t.Fatalf("typed read lost scope: %+v", step)
	}
	if step.Bind != "result" {
		t.Fatalf("read binding lost: %+v", step)
	}
	if _, err := Compile(`web.tab(origin: "https://example.test").getByRole("text").read("staticText")`); err == nil {
		t.Fatal("native staticText accepted on web")
	}
}
