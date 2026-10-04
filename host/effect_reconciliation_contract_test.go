package host

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

func reconciliationActor(t *testing.T) (context.Context, auth.Principal) {
	t.Helper()
	p, err := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
	if err != nil {
		t.Fatal(err)
	}
	return auth.WithPrincipal(context.Background(), p), p
}
func reconciliationString(v string) model.Value {
	return model.Value{Kind: model.StringValue, String: v}
}
func extensionsContext() durable.ReconciliationContext {
	keys := map[string]model.Value{"application": reconciliationString("com.google.Chrome"), "processBirth": reconciliationString("4464:1790968111:309052"), "task": reconciliationString("open-extension-manager")}
	raw, _ := json.Marshal(keys)
	surface := model.Surface{Kind: "native", BundleID: "com.google.Chrome", ProcessID: 4464, ProcessStartToken: "1790968111:309052"}
	name := reconciliationString("Extensions")
	step := model.Step{ID: "open-extensions", Action: "element.press", TimeoutMs: 1000, Target: model.Selector{Surface: surface, Locator: &model.Locator{Strategy: "role", Value: reconciliationString("menuitem"), Name: &name, Exact: true}, Cardinality: "one"}, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: keys}}
	return durable.ReconciliationContext{RunID: "owned-run", PlanID: "original-plan", AttemptID: "original-attempt", EffectID: "original-effect", BusinessKey: string(raw), Step: step, Plan: model.Plan{SchemaVersion: 1, Surfaces: map[string]model.Surface{"chrome": surface}, Steps: []model.Step{step}}, Values: map[string]model.Value{}}
}
func TestChromeNavigationReconciliationReadsExactResultingDocument(t *testing.T) {
	ctx, p := reconciliationActor(t)
	c := extensionsContext()
	resolver := nativeEffectReconciliationResolver([]string{nativeChromeExtensionsContract})
	contract, err := resolver(ctx, p, c)
	if err != nil {
		t.Fatal(err)
	}
	if contract.ID != nativeChromeExtensionsContract || contract.Predicate.RequiredAuthority != "observational" || contract.Predicate.Scope.Target == nil || contract.Predicate.Scope.Target.Surface != c.Step.Target.Surface {
		t.Fatal("navigation contract widened original effect")
	}
	if contract.Predicate.Inputs["processId"].Number != 4464 || contract.Predicate.Inputs["processStartToken"].String != "1790968111:309052" || contract.Predicate.Inputs["windowTitle"].String != "Extensions - Google Chrome" || contract.Predicate.Inputs["windowRole"].String != "AXWindow" || contract.Predicate.Inputs["selector"].String != "AXWebArea" || contract.Predicate.Inputs["attribute"].String != "name" {
		t.Fatal("native predicate lost exact document/window birth scope")
	}
	reads := 0
	adapter, _ := objective.NewNative(func(_ context.Context, _ auth.Principal, target model.Selector, attribute string) (model.Value, objective.NativeEvidence, error) {
		reads++
		if target.Surface != c.Step.Target.Surface || target.Scope.Window["title"].String != "Extensions - Google Chrome" || target.Scope.Window["role"].String != "AXWindow" || target.Locator.Strategy != "role" || target.Locator.Value.String != "AXWebArea" || target.Locator.Name.String != "Extensions" || attribute != "name" {
			t.Fatalf("read broadened %+v", target)
		}
		return reconciliationString("Extensions"), objective.NativeEvidence{HelperEpoch: "fresh-epoch", TargetRef: "fresh-webarea", ObservedAt: time.Now()}, nil
	})
	evaluator, _ := objective.New(map[string]objective.Enrollment{"native": adapter.Enrollment()})
	result, err := evaluator.Evaluate(ctx, p, contract.Predicate, c.Values)
	if err != nil || result.Truth != objective.True || result.Authority != objective.Observational || reads != 1 {
		t.Fatalf("qualified read failed %+v %v", result, err)
	}
	if objective.RequireBusinessSuccess(result) == nil {
		t.Fatal("navigation proved installation/business success")
	}
	// Enrollment is copied; changing the caller slice cannot activate another contract.
	allow := []string{nativeChromeExtensionsContract}
	frozen := nativeEffectReconciliationResolver(allow)
	allow[0] = declaredEffectReconciliationContract
	if _, err := frozen(ctx, p, c); err != nil {
		t.Fatal("caller slice changed trusted enrollment")
	}
}
func TestChromeNavigationReconciliationRejectsOtherEffects(t *testing.T) {
	ctx, p := reconciliationActor(t)
	resolver := nativeEffectReconciliationResolver([]string{nativeChromeExtensionsContract})
	for _, tc := range []struct {
		name   string
		change func(*durable.ReconciliationContext)
	}{
		{"fill", func(c *durable.ReconciliationContext) { c.Step.Action = "element.fill" }},
		{"native-root", func(c *durable.ReconciliationContext) { c.Step.Target.Scope.NativeRoot = "menuBar" }},
		{"button", func(c *durable.ReconciliationContext) { c.Step.Target.Locator.Value = reconciliationString("button") }},
		{"name-only", func(c *durable.ReconciliationContext) { c.Step.Target.Locator.Strategy = "name" }},
		{"other-menu", func(c *durable.ReconciliationContext) { *c.Step.Target.Locator.Name = reconciliationString("Settings") }},
		{"partial-name", func(c *durable.ReconciliationContext) { c.Step.Target.Locator.Exact = false }},
		{"role-reference", func(c *durable.ReconciliationContext) {
			c.Step.Target.Locator.Value = model.Value{Kind: model.ReferenceValue, Ref: "input.role"}
			c.Values["input.role"] = reconciliationString("menuitem")
		}},
		{"name-reference", func(c *durable.ReconciliationContext) {
			*c.Step.Target.Locator.Name = model.Value{Kind: model.ReferenceValue, Ref: "input.name"}
			c.Values["input.name"] = reconciliationString("Extensions")
		}},
		{"other-app", func(c *durable.ReconciliationContext) { c.Step.Target.Surface.BundleID = "com.apple.Safari" }},
		{"web", func(c *durable.ReconciliationContext) {
			c.Step.Target.Surface = model.Surface{Kind: "web", Origin: "https://example.test"}
		}},
		{"unqualified-process", func(c *durable.ReconciliationContext) {
			c.Step.Target.Surface.ProcessID = 0
			c.Step.Target.Surface.ProcessStartToken = ""
		}},
		{"bad-birth", func(c *durable.ReconciliationContext) { c.Step.Target.Surface.ProcessStartToken = "start" }},
		{"other-birth", func(c *durable.ReconciliationContext) { c.Step.Target.Surface.ProcessStartToken = "1790968111:309053" }},
		{"window", func(c *durable.ReconciliationContext) {
			c.Step.Target.Scope.Window = map[string]model.Value{"title": reconciliationString("other")}
		}},
		{"frame", func(c *durable.ReconciliationContext) {
			c.Step.Target.Scope.Frame = map[string]model.Value{"id": reconciliationString("frame")}
		}},
		{"ancestor", func(c *durable.ReconciliationContext) {
			s := c.Step.Target
			s.Ancestor = nil
			c.Step.Target.Ancestor = &s
		}},
		{"plural", func(c *durable.ReconciliationContext) { c.Step.Target.Cardinality = "all"; c.Step.Target.Limit = 10 }},
		{"arguments", func(c *durable.ReconciliationContext) {
			c.Step.Arguments = map[string]model.Value{"force": {Kind: model.BoolValue, Bool: true}}
		}},
		{"bound-output", func(c *durable.ReconciliationContext) { c.Step.Bind = "output" }},
		{"original-output", func(c *durable.ReconciliationContext) { v := reconciliationString("old-output"); c.Original.Value = &v }},
		{"result-type", func(c *durable.ReconciliationContext) { c.Step.ResultType = model.StringValue }},
		{"wrong-task", func(c *durable.ReconciliationContext) {
			c.Step.Effect.BusinessKey["task"] = reconciliationString("install-extension")
		}},
		{"extra-key", func(c *durable.ReconciliationContext) {
			c.Step.Effect.BusinessKey["extra"] = reconciliationString("value")
		}},
		{"spoofed-ledger", func(c *durable.ReconciliationContext) { c.BusinessKey = "{}" }},
		{"wrong-class", func(c *durable.ReconciliationContext) { c.Step.Effect.Class = model.IdempotentMutation }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := extensionsContext()
			tc.change(&c)
			if _, err := resolver(ctx, p, c); err == nil {
				t.Fatal("unqualified/spoofed action adopted")
			}
		})
	}
	for _, allow := range [][]string{nil, {declaredEffectReconciliationContract}, {"unknown.contract"}, {nativeChromeExtensionsContract, nativeChromeExtensionsContract}} {
		if _, err := nativeEffectReconciliationResolver(allow)(ctx, p, extensionsContext()); err == nil {
			t.Fatal("missing/invalid enrollment adopted effect")
		}
	}
	other, _ := auth.NewPrincipal("fixture", "", "bob", nil)
	if _, err := resolver(ctx, other, extensionsContext()); err == nil {
		t.Fatal("foreign principal used trusted resolver")
	}
}
func declaredContext() durable.ReconciliationContext {
	c := extensionsContext()
	predicate := model.Predicate{Kind: "adapter", Adapter: "native", Name: "valueEquals", Scope: model.PredicateScope{SurfaceRef: "chrome"}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "observational", Inputs: map[string]model.Value{"bundleID": reconciliationString("com.google.Chrome"), "processId": {Kind: model.NumberValue, Number: 4464}, "processStartToken": reconciliationString("1790968111:309052"), "strategy": reconciliationString("id"), "selector": reconciliationString("result"), "attribute": reconciliationString("name"), "expected": reconciliationString("ready")}}
	c.Step.Effect.Reconcile = &predicate
	return c
}
func TestDeclaredNativeReconciliationPinsActualPredicateTarget(t *testing.T) {
	ctx, p := reconciliationActor(t)
	resolver := nativeEffectReconciliationResolver([]string{declaredEffectReconciliationContract, nativeChromeExtensionsContract})
	c := declaredContext()
	c.Step.Effect.Reconcile.Inputs["processId"] = model.Value{Kind: model.ReferenceValue, Ref: "input.pid", Expected: model.NumberValue}
	c.Values["input.pid"] = model.Value{Kind: model.NumberValue, Number: 4464}
	contract, err := resolver(ctx, p, c)
	if err != nil || contract.ID != declaredEffectReconciliationContract || contract.Predicate.Inputs["processId"].Kind != model.NumberValue {
		t.Fatalf("valid original predicate rejected %+v %v", contract, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*durable.ReconciliationContext)
	}{
		{"scope-weak", func(c *durable.ReconciliationContext) {
			s := c.Plan.Surfaces["chrome"]
			s.ProcessID = 0
			s.ProcessStartToken = ""
			c.Plan.Surfaces["chrome"] = s
		}},
		{"native-root-broadened", func(c *durable.ReconciliationContext) {
			c.Step.Target.Scope.Window = nil
			c.Step.Target.Scope.NativeRoot = "focusedElement"
		}},
		{"scope-app", func(c *durable.ReconciliationContext) {
			s := c.Plan.Surfaces["chrome"]
			s.BundleID = "com.apple.Safari"
			c.Plan.Surfaces["chrome"] = s
		}},
		{"input-app", func(c *durable.ReconciliationContext) {
			c.Step.Effect.Reconcile.Inputs["bundleID"] = reconciliationString("com.apple.Safari")
		}},
		{"input-pid", func(c *durable.ReconciliationContext) {
			c.Step.Effect.Reconcile.Inputs["processId"] = model.Value{Kind: model.NumberValue, Number: 99}
		}},
		{"input-birth", func(c *durable.ReconciliationContext) {
			c.Step.Effect.Reconcile.Inputs["processStartToken"] = reconciliationString("1790968111:309053")
		}},
		{"partial-pair", func(c *durable.ReconciliationContext) { delete(c.Step.Effect.Reconcile.Inputs, "processId") }},
		{"unknown-ref", func(c *durable.ReconciliationContext) {
			c.Step.Effect.Reconcile.Inputs["bundleID"] = model.Value{Kind: model.ReferenceValue, Ref: "input.foreign"}
		}},
		{"spoofed-ref", func(c *durable.ReconciliationContext) {
			c.Step.Effect.Reconcile.Inputs["processId"] = model.Value{Kind: model.ReferenceValue, Ref: "input.pid", Expected: model.NumberValue}
			c.Values["input.pid"] = model.Value{Kind: model.NumberValue, Number: 99}
		}},
		{"broaden-window", func(c *durable.ReconciliationContext) {
			c.Step.Target.Scope.Window = map[string]model.Value{"title": reconciliationString("Original")}
		}},
		{"unrelated-contract", func(c *durable.ReconciliationContext) {
			c.Step.Effect.Reconcile.Adapter = "native"
			c.Step.Effect.Reconcile.Name = "clipboardEquals"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := declaredContext()
			tc.change(&bad)
			if _, err := resolver(ctx, p, bad); err == nil {
				t.Fatal("weakened original predicate adopted")
			}
		})
	}
	// An invalid original declaration never falls back to the separately enrolled menu contract.
	c = declaredContext()
	c.Step.Effect.Reconcile.Inputs["processStartToken"] = reconciliationString("1790968111:309053")
	if _, err := resolver(ctx, p, c); err == nil {
		t.Fatal("invalid original predicate fell back to menu adoption")
	}
}
func TestDeclaredAuthoritativeReconciliationRequiresOriginalBusinessKey(t *testing.T) {
	ctx, p := reconciliationActor(t)
	c := declaredContext()
	c.Step.Effect.Reconcile.Adapter = "qualified-business-source"
	c.Step.Effect.Reconcile.Name = "originalEffectCompleted"
	c.Step.Effect.Reconcile.RequiredAuthority = "authoritative"
	c.Step.Effect.Reconcile.Inputs = map[string]model.Value{"businessKey": reconciliationString(c.BusinessKey)}
	resolver := nativeEffectReconciliationResolver([]string{declaredEffectReconciliationContract})
	if _, err := resolver(ctx, p, c); err != nil {
		t.Fatal(err)
	}
	c.Step.Effect.Reconcile.Inputs["businessKey"] = reconciliationString(strings.Repeat("x", 10))
	if _, err := resolver(ctx, p, c); err == nil {
		t.Fatal("unrelated business entity adopted")
	}
}

func TestNativeReconciliationEnrollmentFailsAtConfigurationBoundary(t *testing.T) {
	for _, valid := range [][]string{nil, {declaredEffectReconciliationContract}, {nativeChromeExtensionsContract, declaredEffectReconciliationContract}} {
		if err := validateNativeEffectReconciliationEnrollment(valid); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range [][]string{{"unknown.contract"}, {nativeChromeExtensionsContract, nativeChromeExtensionsContract}, make([]string, 65)} {
		if validateNativeEffectReconciliationEnrollment(invalid) == nil {
			t.Fatal("invalid enrollment accepted by host configuration validator")
		}
	}
}

func TestDeclaredNonNativeObservationCannotConfirmOriginalEffect(t *testing.T) {
	ctx, p := reconciliationActor(t)
	c := declaredContext()
	c.Step.Effect.Reconcile.Adapter = "other-ui-source"
	c.Step.Effect.Reconcile.Name = "looksCompleted"
	c.Step.Effect.Reconcile.Inputs = map[string]model.Value{"businessKey": reconciliationString(c.BusinessKey)}
	resolver := nativeEffectReconciliationResolver([]string{declaredEffectReconciliationContract})
	if _, err := resolver(ctx, p, c); err == nil {
		t.Fatal("unenrolled weaker UI adapter confirmed original native effect")
	}
	c.Step.Effect.Reconcile.RequiredAuthority = "authoritative"
	if _, err := resolver(ctx, p, c); err != nil {
		t.Fatal(err)
	}
	delete(c.Step.Effect.Reconcile.Inputs, "businessKey")
	if _, err := resolver(ctx, p, c); err == nil {
		t.Fatal("non-native authoritative source lacked original business identity")
	}
}

func TestChromeNavigationBirthKeyIncludesOriginalPID(t *testing.T) {
	ctx, p := reconciliationActor(t)
	resolver := nativeEffectReconciliationResolver([]string{nativeChromeExtensionsContract})
	for _, birth := range []string{"1790968111:309052", "33409:1790968111:309052", "4464:1790968111:309053"} {
		c := extensionsContext()
		c.Step.Effect.BusinessKey["processBirth"] = reconciliationString(birth)
		raw, _ := json.Marshal(c.Step.Effect.BusinessKey)
		c.BusinessKey = string(raw)
		if _, err := resolver(ctx, p, c); err == nil {
			t.Fatalf("wrong birth identity adopted %q", birth)
		}
	}
	if _, err := resolver(ctx, p, extensionsContext()); err != nil {
		t.Fatal(err)
	}
}

func scopedOriginalPostconditionContext(root string, explicit bool) durable.ReconciliationContext {
	c := declaredContext()
	c.Step.Effect.Reconcile = nil
	c.Step.Target.Scope.NativeRoot = root
	predicate := model.Predicate{Kind: "adapter", Adapter: "native", Name: "valueEquals", Scope: model.PredicateScope{SurfaceRef: "chrome"}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "observational", Inputs: map[string]model.Value{
		"bundleID": reconciliationString(c.Step.Target.Surface.BundleID), "processId": {Kind: model.NumberValue, Number: int64(c.Step.Target.Surface.ProcessID)}, "processStartToken": reconciliationString(c.Step.Target.Surface.ProcessStartToken),
		"nativeRoot": reconciliationString(root), "strategy": reconciliationString("role"), "selector": reconciliationString("menuitem"), "name": reconciliationString("Save As..."), "attribute": reconciliationString("enabled"), "expected": {Kind: model.BoolValue, Bool: true},
	}}
	if explicit {
		target, _ := nativeReconciliationReadTarget(predicate.Inputs)
		predicate.Scope = model.PredicateScope{Target: &target}
	}
	c.Step.Postcondition = &predicate
	return c
}
func TestOriginalScopedPostconditionReconcilesExactReadThroughSurfaceAliasOrTarget(t *testing.T) {
	ctx, p := reconciliationActor(t)
	resolver := nativeEffectReconciliationResolver([]string{declaredPostconditionReconciliationContract})
	for _, root := range []string{"menuBar", "focusedElement"} {
		for _, explicit := range []bool{false, true} {
			c := scopedOriginalPostconditionContext(root, explicit)
			contract, err := resolver(ctx, p, c)
			if err != nil || contract.ID != declaredPostconditionReconciliationContract || contract.Predicate.Inputs["nativeRoot"].String != root {
				t.Fatalf("original scoped predicate rejected: root=%s explicit=%t err=%v", root, explicit, err)
			}
			reads := 0
			adapter, _ := objective.NewNative(func(_ context.Context, _ auth.Principal, target model.Selector, attribute string) (model.Value, objective.NativeEvidence, error) {
				reads++
				if target.Scope.NativeRoot != root || target.Surface != c.Step.Target.Surface || len(target.Scope.Window) != 0 || len(target.Scope.Frame) != 0 || target.Locator.Name == nil || target.Locator.Name.String != "Save As..." || attribute != "enabled" {
					t.Fatalf("reconciliation actualread broadened %+v", target)
				}
				return model.Value{Kind: model.BoolValue, Bool: true}, objective.NativeEvidence{HelperEpoch: "helper", TargetRef: "scoped-ref", ObservedAt: time.Now()}, nil
			})
			result, err := adapter.Evaluate(ctx, p, contract.Predicate.Name, contract.Predicate.Inputs)
			if err != nil || reads != 1 || result.Truth != objective.True || result.Authority != objective.Observational || objective.RequireBusinessSuccess(result) == nil {
				t.Fatalf("read lost scoped authority %+v %v", result, err)
			}
		}
	}
}
func TestScopedNativeReconciliationRejectsAllOriginalDeclaredAndActualMismatches(t *testing.T) {
	ctx, p := reconciliationActor(t)
	resolver := nativeEffectReconciliationResolver([]string{declaredPostconditionReconciliationContract})
	for _, test := range []struct {
		name   string
		change func(*durable.ReconciliationContext)
	}{
		{"actual-other-root", func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["nativeRoot"] = reconciliationString("focusedElement")
		}},
		{"actual-root-missing", func(c *durable.ReconciliationContext) { delete(c.Step.Postcondition.Inputs, "nativeRoot") }},
		{"actual-root-unknown", func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["nativeRoot"] = reconciliationString("document")
		}},
		{"actual-root-type", func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["nativeRoot"] = model.Value{Kind: model.BoolValue, Bool: true}
		}},
		{"original-root-missing", func(c *durable.ReconciliationContext) { c.Step.Target.Scope.NativeRoot = "" }},
		{"original-other-root", func(c *durable.ReconciliationContext) { c.Step.Target.Scope.NativeRoot = "focusedElement" }},
		{"actual-window-title", func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["windowTitle"] = reconciliationString("Writer")
		}},
		{"actual-window-role", func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["windowRole"] = reconciliationString("AXWindow")
		}},
		{"actual-frame", func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["frame"] = reconciliationString("foreign")
		}},
		{"actual-pid", func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["processId"] = model.Value{Kind: model.NumberValue, Number: 77}
		}},
		{"actual-birth", func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["processStartToken"] = reconciliationString("1790968111:309053")
		}},
		{"actual-bundle", func(c *durable.ReconciliationContext) {
			c.Step.Postcondition.Inputs["bundleID"] = reconciliationString("com.foreign.App")
		}},
		{"surface-pid", func(c *durable.ReconciliationContext) {
			surface := c.Plan.Surfaces["chrome"]
			surface.ProcessID = 77
			c.Plan.Surfaces["chrome"] = surface
		}},
		{"explicit-no-root", func(c *durable.ReconciliationContext) {
			target, _ := nativeReconciliationReadTarget(c.Step.Postcondition.Inputs)
			target.Scope.NativeRoot = ""
			c.Step.Postcondition.Scope = model.PredicateScope{Target: &target}
		}},
		{"explicit-other-root", func(c *durable.ReconciliationContext) {
			target, _ := nativeReconciliationReadTarget(c.Step.Postcondition.Inputs)
			target.Scope.NativeRoot = "focusedElement"
			c.Step.Postcondition.Scope = model.PredicateScope{Target: &target}
		}},
		{"explicit-window", func(c *durable.ReconciliationContext) {
			target, _ := nativeReconciliationReadTarget(c.Step.Postcondition.Inputs)
			target.Scope.NativeRoot = ""
			target.Scope.Window = map[string]model.Value{"title": reconciliationString("Writer")}
			c.Step.Postcondition.Scope = model.PredicateScope{Target: &target}
		}},
		{"explicit-frame", func(c *durable.ReconciliationContext) {
			target, _ := nativeReconciliationReadTarget(c.Step.Postcondition.Inputs)
			target.Scope.NativeRoot = ""
			target.Scope.Frame = map[string]model.Value{"id": reconciliationString("foreign")}
			c.Step.Postcondition.Scope = model.PredicateScope{Target: &target}
		}},
		{"explicit-pid", func(c *durable.ReconciliationContext) {
			target, _ := nativeReconciliationReadTarget(c.Step.Postcondition.Inputs)
			target.Surface.ProcessID = 77
			c.Step.Postcondition.Scope = model.PredicateScope{Target: &target}
		}},
		{"explicit-root-ancestor", func(c *durable.ReconciliationContext) {
			target, _ := nativeReconciliationReadTarget(c.Step.Postcondition.Inputs)
			target.Ancestor = &model.Selector{Surface: target.Surface, Scope: model.Scope{NativeRoot: "focusedElement"}, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Exact: true, Value: reconciliationString("parent")}}
			c.Step.Postcondition.Scope = model.PredicateScope{Target: &target}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := scopedOriginalPostconditionContext("menuBar", false)
			test.change(&c)
			if _, err := resolver(ctx, p, c); err == nil {
				t.Fatal("genuine scope mismatch admitted")
			}
		})
	}
}
func TestScopedNativeReconciliationAncestorRetainsActualRoot(t *testing.T) {
	c := scopedOriginalPostconditionContext("menuBar", false)
	c.Step.Postcondition.Inputs["ancestorID"] = reconciliationString("parent")
	target, err := nativeReconciliationReadTarget(c.Step.Postcondition.Inputs)
	if err != nil || target.Scope.NativeRoot != "menuBar" || target.Ancestor == nil || target.Ancestor.Scope.NativeRoot != "menuBar" {
		t.Fatalf("ancestor lost actualscope %+v %v", target, err)
	}
}

func TestAppWideWindowKeyOutcomeCanNarrowToOriginalDeclaredFocusRoot(t *testing.T) {
	ctx, p := reconciliationActor(t)
	c := scopedOriginalPostconditionContext("focusedElement", false)
	c.Step.Action = "window.pressSessionKey"
	c.Step.Target.Scope = model.Scope{}
	c.Step.Target.Locator = nil
	c.Step.Target.Ancestor = nil
	c.Step.Arguments = map[string]model.Value{"windowKey": {Kind: model.ObjectValue, Object: map[string]model.Value{"windowId": {Kind: model.NumberValue, Number: 99}, "key": {Kind: model.StringValue, String: "F2"}}}}
	resolver := nativeEffectReconciliationResolver([]string{declaredPostconditionReconciliationContract})
	if _, err := resolver(ctx, p, c); err != nil {
		t.Fatalf("narrow original outcome rejected: %v", err)
	}
	c.Step.Target.Scope.NativeRoot = "menuBar"
	if _, err := resolver(ctx, p, c); err == nil {
		t.Fatal("different original root accepted")
	}
}
