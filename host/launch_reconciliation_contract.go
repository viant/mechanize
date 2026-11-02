package host

import (
	"encoding/json"
	"errors"

	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
)

// A lost launch reply cannot be recovered by adopting whichever app is running
// now. Only an identity persisted from the original authenticated reply qualifies.
func launchReconciliation(c durable.ReconciliationContext) (durable.ReconciliationContract, error) {
	s, t := c.Step, c.Step.Target
	if s.Action != "app.open" || s.Validate() != nil || s.Effect.Class != model.ExternalNonIdempotent || s.Effect.Reconcile != nil || s.Postcondition != nil || len(s.Arguments) != 0 || t.Surface.ProcessID != 0 || t.Surface.ProcessStartToken != "" || t.Locator != nil || t.Ancestor != nil || t.Index != nil || t.Limit != 0 || t.Order != "" || t.Cardinality != "one" || t.Scope.NativeRoot != "" || t.Scope.NativeMenu != "" || len(t.Scope.Window) != 0 || len(t.Scope.Frame) != 0 {
		return durable.ReconciliationContract{}, errors.New("launch adoption requires the unchanged bundle-only launch action")
	}
	v := c.Original.Value
	if v == nil || v.Kind != model.ObjectValue || v.Validate() != nil || len(v.Object) != 5 || (c.Original.DispatchState != "dispatched" && c.Original.DispatchState != "unknown") || c.Original.VerificationState != "unknown" {
		return durable.ReconciliationContract{}, errors.New("original launch receipt identity unavailable; current app presence cannot reconcile a lost receipt")
	}
	bundle, pid, token, launch, active := v.Object["bundleID"], v.Object["pid"], v.Object["startToken"], v.Object["launchTime"], v.Object["active"]
	if bundle.Kind != model.StringValue || bundle.String != t.Surface.BundleID || pid.Kind != model.NumberValue || pid.Number <= 0 || pid.Number > 2147483647 || token.Kind != model.StringValue || launch.Kind != model.StringValue || launch.String != "kernel:"+token.String || active.Kind != model.BoolValue {
		return durable.ReconciliationContract{}, errors.New("original launch receipt process identity is invalid")
	}
	surface := model.Surface{Kind: "native", BundleID: bundle.String, ProcessID: int(pid.Number), ProcessStartToken: token.String}
	scope := model.Selector{Surface: surface, Cardinality: "one"}
	if err := scope.Validate(); err != nil {
		return durable.ReconciliationContract{}, err
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
		return durable.ReconciliationContract{}, errors.New("original launch business identity mismatch")
	}
	contract := durable.ReconciliationContract{ID: nativeLaunchContract, Version: "1", Predicate: model.Predicate{Kind: "adapter", Adapter: "nativeLaunchProcess", Name: "running", Inputs: map[string]model.Value{"bundleID": bundle, "processId": pid, "processStartToken": token}, Scope: model.PredicateScope{Target: &scope}, TimeoutMs: 5000, FreshnessMs: 3000, RequiredAuthority: "observational"}}
	_, err = contract.Hash()
	return contract, err
}
