package host

import (
	"encoding/json"
	"errors"

	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
)

// The original plan must already contain the PID and birth. A bundle-only quit
// cannot be reconciled by selecting whichever application is running later.
func quitReconciliation(c durable.ReconciliationContext) (durable.ReconciliationContract, error) {
	s := c.Step
	t := s.Target
	if s.Action != "app.quit" || s.Validate() != nil || s.Effect.Class != model.ExternalNonIdempotent || s.Effect.Reconcile != nil || s.Postcondition != nil || c.Original.Value != nil || t.Surface.ProcessID <= 0 || t.Surface.ValidateProcessIdentity() != nil || t.Locator != nil || t.Ancestor != nil || t.Index != nil || t.Limit != 0 || t.Order != "" || t.Cardinality != "one" || t.Scope.NativeRoot != "" || len(t.Scope.Window) != 0 || len(t.Scope.Frame) != 0 {
		return durable.ReconciliationContract{}, errors.New("quit adoption requires the unchanged exact original process and normal quit action")
	}
	key := map[string]model.Value{}
	for name, value := range s.Effect.BusinessKey {
		resolved, err := model.ResolveValue(value, c.Values)
		if err != nil {
			return durable.ReconciliationContract{}, err
		}
		key[name] = resolved
	}
	raw, err := json.Marshal(key)
	if err != nil || len(key) == 0 || string(raw) != c.BusinessKey {
		return durable.ReconciliationContract{}, errors.New("original quit business identity mismatch")
	}
	inputs := map[string]model.Value{"bundleID": {Kind: model.StringValue, String: t.Surface.BundleID}, "processId": {Kind: model.NumberValue, Number: int64(t.Surface.ProcessID)}, "processStartToken": {Kind: model.StringValue, String: t.Surface.ProcessStartToken}}
	scope := model.Selector{Surface: t.Surface, Cardinality: "one"}
	contract := durable.ReconciliationContract{ID: nativeQuitContract, Version: "1", Predicate: model.Predicate{Kind: "adapter", Adapter: "nativeProcess", Name: "exited", Inputs: inputs, Scope: model.PredicateScope{Target: &scope}, TimeoutMs: 5000, FreshnessMs: 3000, RequiredAuthority: "observational"}}
	_, err = contract.Hash()
	return contract, err
}
