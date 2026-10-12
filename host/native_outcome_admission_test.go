package host

import (
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"testing"
)

func TestNativeOutcomeAdmissionReusesImmutableReconciliationBoundaries(t *testing.T) {
	ctx, p := reconciliationActor(t)
	guard := nativeStepOutcomeAdmission([]string{declaredPostconditionReconciliationContract})
	c := scopedOriginalPostconditionContext("focusedElement", false)
	if err := guard(ctx, p, c); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*durable.ReconciliationContext){
		func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["processId"] = model.Value{Kind: model.NumberValue, Number: 999}
		},
		func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["processStartToken"] = reconciliationString("200:2")
		},
		func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["bundleID"] = reconciliationString("other.app")
		},
		func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["nativeRoot"] = reconciliationString("menuBar")
		},
	} {
		bad := scopedOriginalPostconditionContext("focusedElement", false)
		change(&bad)
		if guard(ctx, p, bad) == nil {
			t.Fatal("changed outcome scope admitted")
		}
	}
	// Reconciliation enrollment is frozen; caller edits cannot change admission.
	allowed := []string{declaredPostconditionReconciliationContract}
	frozen := nativeStepOutcomeAdmission(allowed)
	allowed[0] = "invalid-caller-change"
	if err := frozen(ctx, p, c); err != nil {
		t.Fatal(err)
	}
}

func TestFrameOutcomeAdmissionUsesExactWindowWithoutRootSubstitution(t *testing.T) {
	ctx, p := reconciliationActor(t)
	c := scopedOriginalPostconditionContext("focusedElement", false)
	c.Step.Action = "window.clickFrame"
	c.Step.Target.Scope = model.Scope{}
	c.Step.Target.Locator = nil
	c.Step.Arguments = map[string]model.Value{"frameClick": {Kind: model.ObjectValue, Object: map[string]model.Value{"captureRef": reconciliationString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "x": {Kind: model.NumberValue, Number: 10}, "y": {Kind: model.NumberValue, Number: 10}}}}
	inputs := c.Step.Postcondition.Inputs
	delete(inputs, "nativeRoot")
	delete(inputs, "name")
	inputs["windowTitle"] = reconciliationString("Owned fixture")
	inputs["windowRole"] = reconciliationString("AXWindow")
	inputs["strategy"] = reconciliationString("role")
	inputs["selector"] = reconciliationString("AXTextArea")
	inputs["attribute"] = reconciliationString("focused")
	inputs["expected"] = model.Value{Kind: model.BoolValue, Bool: true}
	if err := nativeStepOutcomeAdmission([]string{declaredPostconditionReconciliationContract})(ctx, p, c); err != nil {
		t.Fatal(err)
	}
}
