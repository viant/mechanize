package host

import (
	"errors"
	"reflect"

	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
)

// Focus is a platform-defined UI effect. Its adoption requires fresh independent
// system/app focus equality for the original target, not a newly chosen selector.
func focusReconciliation(c durable.ReconciliationContext) (durable.ReconciliationContract, error) {
	s := c.Step
	target := s.Target
	if s.Action != "element.focus" || s.Bind != "" || s.ResultType != "" || c.Original.Value != nil || len(s.Arguments) != 0 || s.Effect.Class != model.ExternalNonIdempotent || c.BusinessKey == "" || target.Locator == nil || !target.Locator.Exact || target.Cardinality != "one" || target.Index != nil || target.Limit != 0 || target.Order != "" || len(target.Scope.Frame) > 0 {
		return durable.ReconciliationContract{}, errors.New("original effect is not exact native focus")
	}
	text := func(v string) model.Value { return model.Value{Kind: model.StringValue, String: v} }
	inputs := map[string]model.Value{"bundleID": text(target.Surface.BundleID), "processId": {Kind: model.NumberValue, Number: int64(target.Surface.ProcessID)}, "processStartToken": text(target.Surface.ProcessStartToken), "strategy": text(target.Locator.Strategy), "attribute": text("focused"), "expected": {Kind: model.BoolValue, Bool: true}}
	var err error
	inputs["selector"], err = model.ResolveValue(target.Locator.Value, c.Values)
	if err != nil {
		return durable.ReconciliationContract{}, err
	}
	if target.Locator.Name != nil {
		inputs["name"], err = model.ResolveValue(*target.Locator.Name, c.Values)
		if err != nil {
			return durable.ReconciliationContract{}, err
		}
	}
	for key, value := range target.Scope.Window {
		field := ""
		switch key {
		case "title":
			field = "windowTitle"
		case "role":
			field = "windowRole"
		default:
			return durable.ReconciliationContract{}, errors.New("focus window scope is not qualified")
		}
		inputs[field], err = model.ResolveValue(value, c.Values)
		if err != nil {
			return durable.ReconciliationContract{}, err
		}
	}
	if target.Ancestor != nil {
		a := target.Ancestor
		if a.Ancestor != nil || a.Surface != target.Surface || a.Cardinality != "one" || a.Index != nil || a.Limit != 0 || a.Order != "" || a.Locator == nil || a.Locator.Strategy != "id" || !a.Locator.Exact || a.Locator.Name != nil || !reflect.DeepEqual(a.Scope, target.Scope) {
			return durable.ReconciliationContract{}, errors.New("focus ancestor scope is not qualified")
		}
		inputs["ancestorID"], err = model.ResolveValue(a.Locator.Value, c.Values)
		if err != nil {
			return durable.ReconciliationContract{}, err
		}
	}
	readTarget, err := nativeReconciliationReadTarget(inputs)
	if err != nil {
		return durable.ReconciliationContract{}, err
	}
	contract := durable.ReconciliationContract{ID: nativeFocusContract, Version: "1", Predicate: model.Predicate{Kind: "adapter", Adapter: "native", Name: "valueEquals", Inputs: inputs, Scope: model.PredicateScope{Target: &readTarget}, TimeoutMs: 5000, FreshnessMs: 3000, RequiredAuthority: "observational"}}
	_, err = contract.Hash()
	return contract, err
}
