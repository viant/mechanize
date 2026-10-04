package host

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
)

const nativeChromeExtensionsContract = "native.chrome.openExtensions.v1"
const declaredEffectReconciliationContract = "plan.effect.reconcile"
const declaredPostconditionReconciliationContract = "plan.postcondition.reconcile"
const nativeFocusContract = "native.focus.v1"

func validateNativeEffectReconciliationEnrollment(allowed []string) error {
	if len(allowed) > 64 {
		return errors.New("reconciliation enrollment exceeds bounds")
	}
	seen := map[string]bool{}
	for _, id := range allowed {
		if (id != nativeChromeExtensionsContract && id != declaredEffectReconciliationContract && id != declaredPostconditionReconciliationContract && id != nativeFocusContract) || seen[id] {
			return errors.New("unknown or duplicate native reconciliation enrollment")
		}
		seen[id] = true
	}
	return nil
}

// This resolver selects code-enrolled read contracts only. The caller holds the
// stopped-runtime guard; the evaluator supplies fresh independently scoped reads.
func nativeEffectReconciliationResolver(allowed []string) func(context.Context, auth.Principal, durable.ReconciliationContext) (durable.ReconciliationContract, error) {
	configurationErr := validateNativeEffectReconciliationEnrollment(allowed)
	enrolled := map[string]bool{}
	for _, id := range allowed {
		enrolled[id] = true
	}
	return func(ctx context.Context, p auth.Principal, c durable.ReconciliationContext) (durable.ReconciliationContract, error) {
		actual, err := auth.FromContext(ctx)
		if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
			return durable.ReconciliationContract{}, auth.ErrUnauthorized
		}
		if configurationErr != nil {
			return durable.ReconciliationContract{}, configurationErr
		}
		surface := c.Step.Target.Surface
		if surface.Kind != "native" || surface.BundleID == "" || surface.Origin != "" || surface.TabID != "" || surface.Title != "" || surface.ProcessID == 0 || surface.ValidateProcessIdentity() != nil || c.Step.Validate() != nil {
			return durable.ReconciliationContract{}, errors.New("exact original native process fingerprint required")
		}
		if c.Step.Effect.Reconcile != nil {
			if !enrolled[declaredEffectReconciliationContract] {
				return durable.ReconciliationContract{}, errors.New("declared effect reconciliation is not enrolled")
			}
			return declaredNativeReconciliation(c)
		}
		// Without generic enrollment, existing action-specific contracts retain
		// their original behavior. With it, invalid original predicates fail closed.
		if c.Step.Postcondition != nil && enrolled[declaredPostconditionReconciliationContract] {
			contract, err := durable.DeclaredPostconditionReconciliation(c)
			if err != nil {
				return durable.ReconciliationContract{}, err
			}
			if contract.Predicate.Adapter != "native" || contract.Predicate.Name != "valueEquals" {
				return durable.ReconciliationContract{}, errors.New("original native valueEquals postcondition required")
			}
			return validateDeclaredNativeReconciliation(c, contract)
		}
		if c.Step.Action == "element.focus" {
			if !enrolled[nativeFocusContract] {
				return durable.ReconciliationContract{}, errors.New("native focus reconciliation is not enrolled")
			}
			return focusReconciliation(c)
		}
		if !enrolled[nativeChromeExtensionsContract] {
			return durable.ReconciliationContract{}, errors.New("qualified native navigation reconciliation is not enrolled")
		}
		return chromeExtensionsReconciliation(c)
	}
}

func resolvedReconciliationInputs(c durable.ReconciliationContext, p model.Predicate) (map[string]model.Value, error) {
	out := make(map[string]model.Value, len(p.Inputs))
	for key, value := range p.Inputs {
		resolved, err := model.ResolveValue(value, c.Values)
		if err != nil {
			return nil, err
		}
		out[key] = resolved
	}
	return out, nil
}
func nativePredicateScope(c durable.ReconciliationContext, p model.Predicate) (model.Selector, error) {
	if err := p.Validate(); err != nil {
		return model.Selector{}, err
	}
	if p.Scope.Target != nil {
		return *p.Scope.Target, nil
	}
	surface, ok := c.Plan.Surfaces[p.Scope.SurfaceRef]
	if !ok {
		return model.Selector{}, errors.New("original predicate surface alias unavailable")
	}
	return model.Selector{Surface: surface, Cardinality: "one"}, nil
}
func declaredNativeReconciliation(c durable.ReconciliationContext) (durable.ReconciliationContract, error) {
	contract, err := durable.DeclaredReconciliation(c)
	if err != nil {
		return contract, err
	}
	return validateDeclaredNativeReconciliation(c, contract)
}
func validateDeclaredNativeReconciliation(c durable.ReconciliationContext, contract durable.ReconciliationContract) (durable.ReconciliationContract, error) {
	scope, err := nativePredicateScope(c, contract.Predicate)
	if err != nil {
		return durable.ReconciliationContract{}, err
	}
	if scope.Surface != c.Step.Target.Surface || scope.Cardinality != "one" || len(scope.Scope.Frame) != 0 {
		return durable.ReconciliationContract{}, errors.New("declared reconciliation must retain the exact native process scope")
	}
	inputs, err := resolvedReconciliationInputs(c, contract.Predicate)
	if err != nil {
		return durable.ReconciliationContract{}, err
	}
	if contract.Predicate.Adapter != "native" && contract.Predicate.RequiredAuthority != "authoritative" {
		return durable.ReconciliationContract{}, errors.New("non-native reconciliation requires an authoritative business source")
	}
	if contract.Predicate.RequiredAuthority == "authoritative" {
		key, ok := inputs["businessKey"]
		if !ok || key.Kind != model.StringValue || key.String != c.BusinessKey || c.BusinessKey == "" {
			return durable.ReconciliationContract{}, errors.New("authoritative reconciliation must bind the original canonical business key")
		}
	}
	if contract.Predicate.Adapter == "native" {
		if contract.Predicate.Name != "valueEquals" {
			return durable.ReconciliationContract{}, errors.New("native reconciliation read is not qualified")
		}
		target, err := nativeReconciliationReadTarget(inputs)
		if err != nil {
			return durable.ReconciliationContract{}, err
		}
		if target.Surface != c.Step.Target.Surface {
			return durable.ReconciliationContract{}, errors.New("native predicate inputs changed original app or process birth")
		}
		// An explicit CG-window key may declare a narrower result root (for example a
		// window key opening a focused editor). An already scoped original
		// action cannot broaden or substitute its root.
		if (c.Step.Action != "window.pressSessionKey" || c.Step.Target.Scope.NativeRoot != "") && target.Scope.NativeRoot != c.Step.Target.Scope.NativeRoot || contract.Predicate.Scope.Target != nil && scope.Scope.NativeRoot != target.Scope.NativeRoot {
			return durable.ReconciliationContract{}, errors.New("native predicate must preserve the original root scope")
		}
		if len(c.Step.Target.Scope.Window) > 0 && !sameReconciliationWindow(c.Step.Target.Scope.Window, target.Scope.Window, c.Values) {
			return durable.ReconciliationContract{}, errors.New("native predicate broadened the original window boundary")
		}
		if len(scope.Scope.Window) > 0 && !sameReconciliationWindow(scope.Scope.Window, target.Scope.Window, c.Values) {
			return durable.ReconciliationContract{}, errors.New("native predicate inputs differ from declared window scope")
		}
		if scope.Locator != nil && !reflect.DeepEqual(scope.Locator, target.Locator) {
			return durable.ReconciliationContract{}, errors.New("native predicate inputs differ from declared read locator")
		}
		if scope.Ancestor != nil && !reflect.DeepEqual(scope.Ancestor, target.Ancestor) {
			return durable.ReconciliationContract{}, errors.New("native predicate inputs differ from declared ancestor")
		}
		if c.Step.Target.Ancestor != nil && !reflect.DeepEqual(c.Step.Target.Ancestor, target.Ancestor) {
			return durable.ReconciliationContract{}, errors.New("native predicate broadened the original ancestor boundary")
		}
	}
	// Freeze resolved typed data after checking scope. No input can select an adapter implementation.
	contract.Predicate.Inputs = inputs
	if _, err := contract.Hash(); err != nil {
		return durable.ReconciliationContract{}, err
	}
	return contract, nil
}
func sameReconciliationWindow(a, b map[string]model.Value, values map[string]model.Value) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	resolved := func(v map[string]model.Value) (map[string]model.Value, error) {
		out := map[string]model.Value{}
		for k, value := range v {
			r, err := model.ResolveValue(value, values)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	}
	left, err := resolved(a)
	if err != nil {
		return false
	}
	right, err := resolved(b)
	return err == nil && reflect.DeepEqual(left, right)
}
func nativeReconciliationReadTarget(inputs map[string]model.Value) (model.Selector, error) {
	allowed := map[string]bool{"bundleID": true, "processId": true, "processStartToken": true, "strategy": true, "selector": true, "name": true, "nativeRoot": true, "windowTitle": true, "windowRole": true, "ancestorID": true, "attribute": true, "expected": true}
	for key := range inputs {
		if !allowed[key] {
			return model.Selector{}, errors.New("unsupported native reconciliation input")
		}
	}
	text := func(key string) (string, error) {
		value, ok := inputs[key]
		if !ok || value.Kind != model.StringValue || value.String == "" {
			return "", errors.New("typed native reconciliation string required")
		}
		return value.String, nil
	}
	bundle, err := text("bundleID")
	if err != nil {
		return model.Selector{}, err
	}
	token, err := text("processStartToken")
	if err != nil {
		return model.Selector{}, err
	}
	pid, ok := inputs["processId"]
	if !ok || pid.Kind != model.NumberValue || pid.Number <= 0 || pid.Number > 2147483647 {
		return model.Selector{}, errors.New("native reconciliation requires complete process fingerprint")
	}
	strategy, err := text("strategy")
	if err != nil {
		return model.Selector{}, err
	}
	selector, err := text("selector")
	if err != nil {
		return model.Selector{}, err
	}
	if strategy != "id" && strategy != "name" && strategy != "role" {
		return model.Selector{}, errors.New("native read locator is not qualified")
	}
	target := model.Selector{Surface: model.Surface{Kind: "native", BundleID: bundle, ProcessID: int(pid.Number), ProcessStartToken: token}, Locator: &model.Locator{Strategy: strategy, Value: model.Value{Kind: model.StringValue, String: selector}, Exact: true}, Cardinality: "one"}
	if _, exists := inputs["name"]; exists {
		name, err := text("name")
		if err != nil || strategy != "role" {
			return model.Selector{}, errors.New("native role name mismatch")
		}
		target.Locator.Name = &model.Value{Kind: model.StringValue, String: name}
	}
	if _, exists := inputs["nativeRoot"]; exists {
		root, err := text("nativeRoot")
		_, windowTitle := inputs["windowTitle"]
		_, windowRole := inputs["windowRole"]
		if err != nil || (root != "menuBar" && root != "focusedElement") || windowTitle || windowRole {
			return model.Selector{}, errors.New("native root requires menuBar or focusedElement without window inputs")
		}
		target.Scope.NativeRoot = root
	}
	if _, exists := inputs["windowTitle"]; exists {
		title, err := text("windowTitle")
		if err != nil {
			return model.Selector{}, err
		}
		target.Scope.Window = map[string]model.Value{"title": {Kind: model.StringValue, String: title}}
	}
	if _, exists := inputs["windowRole"]; exists {
		role, err := text("windowRole")
		if err != nil || len(target.Scope.Window) == 0 || (role != "window" && role != "AXWindow") {
			return model.Selector{}, errors.New("exact native window boundary required")
		}
		target.Scope.Window["role"] = model.Value{Kind: model.StringValue, String: role}
	}
	if _, exists := inputs["ancestorID"]; exists {
		id, err := text("ancestorID")
		if err != nil {
			return model.Selector{}, err
		}
		target.Ancestor = &model.Selector{Surface: target.Surface, Scope: target.Scope, Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: id}, Exact: true}, Cardinality: "one"}
	}
	return target, target.Validate()
}

func chromeExtensionsReconciliation(c durable.ReconciliationContext) (durable.ReconciliationContract, error) {
	step := c.Step
	target := step.Target
	if target.Scope.NativeRoot != "" {
		return durable.ReconciliationContract{}, errors.New("Chrome Extensions v1 reconciliation does not qualify native root scopes")
	}
	locator := target.Locator
	surface := target.Surface
	if step.Action != "element.press" || step.Effect.Class != model.ExternalNonIdempotent || step.Bind != "" || step.ResultType != "" || c.Original.Value != nil || len(step.Arguments) != 0 || surface.BundleID != "com.google.Chrome" || target.Cardinality != "one" || target.Limit != 0 || target.Index != nil || target.Order != "" || target.Ancestor != nil || len(target.Scope.Window) != 0 || len(target.Scope.Frame) != 0 || locator == nil || locator.Strategy != "role" || !locator.Exact || !reflect.DeepEqual(locator.Value, model.Value{Kind: model.StringValue, String: "menuitem"}) || locator.Name == nil || !reflect.DeepEqual(*locator.Name, model.Value{Kind: model.StringValue, String: "Extensions"}) {
		return durable.ReconciliationContract{}, errors.New("original action is not the qualified Chrome Extensions menu navigation")
	}
	expected := map[string]model.Value{"application": {Kind: model.StringValue, String: "com.google.Chrome"}, "processBirth": {Kind: model.StringValue, String: strconv.Itoa(surface.ProcessID) + ":" + surface.ProcessStartToken}, "task": {Kind: model.StringValue, String: "open-extension-manager"}}
	if len(step.Effect.BusinessKey) != len(expected) {
		return durable.ReconciliationContract{}, errors.New("Chrome navigation original business identity mismatch")
	}
	for key, want := range expected {
		value, ok := step.Effect.BusinessKey[key]
		if !ok {
			return durable.ReconciliationContract{}, errors.New("Chrome navigation business identity missing")
		}
		actual, err := model.ResolveValue(value, c.Values)
		if err != nil || !reflect.DeepEqual(actual, want) {
			return durable.ReconciliationContract{}, errors.New("Chrome navigation business identity changed")
		}
	}
	raw, _ := json.Marshal(expected)
	if c.BusinessKey != string(raw) {
		return durable.ReconciliationContract{}, errors.New("Chrome navigation ledger business identity mismatch")
	}
	const title = "Extensions - Google Chrome"
	inputs := map[string]model.Value{"bundleID": {Kind: model.StringValue, String: surface.BundleID}, "processId": {Kind: model.NumberValue, Number: int64(surface.ProcessID)}, "processStartToken": {Kind: model.StringValue, String: surface.ProcessStartToken}, "strategy": {Kind: model.StringValue, String: "role"}, "selector": {Kind: model.StringValue, String: "AXWebArea"}, "name": {Kind: model.StringValue, String: "Extensions"}, "windowTitle": {Kind: model.StringValue, String: title}, "windowRole": {Kind: model.StringValue, String: "AXWindow"}, "attribute": {Kind: model.StringValue, String: "name"}, "expected": {Kind: model.StringValue, String: "Extensions"}}
	readTarget, err := nativeReconciliationReadTarget(inputs)
	if err != nil {
		return durable.ReconciliationContract{}, err
	}
	contract := durable.ReconciliationContract{ID: nativeChromeExtensionsContract, Version: "1", Predicate: model.Predicate{Kind: "adapter", Adapter: "native", Name: "valueEquals", Inputs: inputs, Scope: model.PredicateScope{Target: &readTarget}, TimeoutMs: 5000, FreshnessMs: 3000, RequiredAuthority: "observational"}}
	_, err = contract.Hash()
	return contract, err
}
