package objective

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
	"time"
)

func nativeInputs() map[string]model.Value {
	out := map[string]model.Value{}
	for k, v := range map[string]string{"bundleID": "com.example.Calculator", "strategy": "id", "selector": "display", "attribute": "value", "expected": "42"} {
		out[k] = model.Value{Kind: model.StringValue, String: v}
	}
	return out
}
func nativePredicate() model.Predicate {
	return model.Predicate{Kind: "adapter", Adapter: "native", Name: "valueEquals", Inputs: nativeInputs(), RequiredAuthority: "observational", TimeoutMs: 1000, FreshnessMs: 1000}
}

func TestNativeStaticTextWindowScope(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	reads := 0
	a, _ := NewNative(func(_ context.Context, _ auth.Principal, target model.Selector, attribute string) (model.Value, NativeEvidence, error) {
		reads++
		if target.Scope.Window["title"].String != "Calculator" || target.Scope.Window["role"].String != "AXWindow" || attribute != "staticText" || target.Ancestor == nil || target.Ancestor.Locator.Value.String != "StandardResultView" || target.Ancestor.Scope.Window["title"].String != "Calculator" {
			t.Fatalf("scope or attribute changed: %+v / %s", target, attribute)
		}
		return model.Value{Kind: model.StringValue, String: "42"}, NativeEvidence{HelperEpoch: "fixture", TargetRef: "display", ObservedAt: time.Now()}, nil
	})
	inputs := nativeInputs()
	inputs["attribute"] = model.Value{Kind: model.StringValue, String: "staticText"}
	inputs["windowTitle"] = model.Value{Kind: model.StringValue, String: "Calculator"}
	inputs["windowRole"] = model.Value{Kind: model.StringValue, String: "AXWindow"}
	inputs["ancestorID"] = model.Value{Kind: model.StringValue, String: "StandardResultView"}
	if _, err := a.Evaluate(ctx, p, "valueEquals", inputs); err != nil || reads != 1 {
		t.Fatalf("read=%d error=%v", reads, err)
	}
	delete(inputs, "windowTitle")
	if _, err := a.Evaluate(ctx, p, "valueEquals", inputs); err == nil || reads != 1 {
		t.Fatal("unscoped window role reached native read")
	}
}
func TestNativeValueEqualsIndependentReadOnlyEvidence(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	for _, tc := range []struct {
		name, value string
		time        time.Time
		epoch, ref  string
		err         error
		want        Truth
	}{
		{"equal", "42", time.Now(), "epoch", "ref", nil, True}, {"different", "41", time.Now(), "epoch", "ref", nil, False},
		{"stale", "42", time.Now().Add(-time.Hour), "epoch", "ref", nil, Unknown}, {"missing ref", "42", time.Now(), "epoch", "", nil, Unknown},
		{"future", "42", time.Now().Add(time.Hour), "epoch", "ref", nil, Unknown}, {"unavailable", "", time.Now(), "", "", errors.New("private source detail"), Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			a, err := NewNative(func(_ context.Context, actual auth.Principal, target model.Selector, attribute string) (model.Value, NativeEvidence, error) {
				reads++
				if actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
					t.Fatal("principal changed")
				}
				if target.Surface.BundleID != "com.example.Calculator" || target.Locator.Strategy != "id" || target.Locator.Value.String != "display" || !target.Locator.Exact || target.Cardinality != "one" || attribute != "value" {
					t.Fatalf("read widened %+v %s", target, attribute)
				}
				return model.Value{Kind: model.StringValue, String: tc.value}, NativeEvidence{HelperEpoch: tc.epoch, TargetRef: tc.ref, ObservedAt: tc.time}, tc.err
			})
			if err != nil {
				t.Fatal(err)
			}
			eval, _ := New(map[string]Enrollment{"native": a.Enrollment()})
			result, err := eval.Evaluate(ctx, p, nativePredicate(), nil)
			if err != nil || result.Truth != tc.want || reads != 1 {
				t.Fatalf("result=%+v reads=%d err=%v", result, reads, err)
			}
			if result.Truth == True && result.Authority != Observational {
				t.Fatal("UI read claimed business authority")
			}
			if RequireBusinessSuccess(result) == nil {
				t.Fatal("UI equality became business success")
			}
			for _, e := range result.Evidence {
				if strings.Contains(e.Reference, "42") {
					t.Fatal("read value copied into evidence")
				}
			}
		})
	}
}
func TestNativePredicateRejectsUnclosedInputsBeforeRead(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	reads := 0
	a, _ := NewNative(func(context.Context, auth.Principal, model.Selector, string) (model.Value, NativeEvidence, error) {
		reads++
		return model.Value{}, NativeEvidence{}, nil
	})
	for _, change := range []func(map[string]model.Value){
		func(v map[string]model.Value) { v["script"] = model.Value{Kind: model.StringValue, String: "alert(1)"} },
		func(v map[string]model.Value) { v["strategy"] = model.Value{Kind: model.StringValue, String: "xpath"} },
		func(v map[string]model.Value) {
			v["attribute"] = model.Value{Kind: model.StringValue, String: "clipboard"}
		},
		func(v map[string]model.Value) { v["bundleID"] = model.Value{Kind: model.StringValue, String: "*"} },
		func(v map[string]model.Value) { v["expected"] = model.Value{Kind: model.NumberValue, Number: 42} },
		func(v map[string]model.Value) {
			v["selector"] = model.Value{Kind: model.StringValue, String: strings.Repeat("x", 513)}
		},
		func(v map[string]model.Value) { v["name"] = model.Value{Kind: model.StringValue, String: "display"} },
	} {
		v := nativeInputs()
		change(v)
		if _, err := a.Evaluate(ctx, p, "valueEquals", v); err == nil {
			t.Fatalf("unclosed input accepted %+v", v)
		}
	}
	if reads != 0 {
		t.Fatal("invalid input reached callback")
	}
	other, _ := auth.NewPrincipal("fixture", "", "bob", nil)
	if _, err := a.Evaluate(ctx, other, "valueEquals", nativeInputs()); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("foreign principal read")
	}
	if _, err := NewNative(nil); err == nil {
		t.Fatal("missing source enrolled")
	}
}

func TestNativePredicateExactProcessForwardingAndStaleBirth(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	inputs := nativeInputs()
	inputs["processId"] = model.Value{Kind: model.NumberValue, Number: 42}
	inputs["processStartToken"] = model.Value{Kind: model.StringValue, String: "1790000000:1"}
	inputs["ancestorID"] = model.Value{Kind: model.StringValue, String: "dialog"}
	stale := false
	reads := 0
	a, _ := NewNative(func(_ context.Context, _ auth.Principal, target model.Selector, _ string) (model.Value, NativeEvidence, error) {
		reads++
		if target.Surface.ProcessID != 42 || target.Surface.ProcessStartToken != "1790000000:1" || target.Ancestor == nil || target.Ancestor.Surface != target.Surface {
			t.Fatalf("process narrowing lost: %+v", target)
		}
		if stale {
			return model.Value{}, NativeEvidence{}, &model.MechanizeError{Code: "staleReference", Message: "birth identity changed", DispatchState: "notDispatched"}
		}
		return model.Value{Kind: model.StringValue, String: "42"}, NativeEvidence{HelperEpoch: "epoch", TargetRef: "fresh-ref", ObservedAt: time.Now()}, nil
	})
	if result, err := a.Evaluate(ctx, p, "valueEquals", inputs); err != nil || result.Truth != True || reads != 1 {
		t.Fatalf("forwarded read failed %+v %v", result, err)
	}
	stale = true
	if _, err := a.Evaluate(ctx, p, "valueEquals", inputs); err == nil {
		t.Fatal("stale process birth produced evidence")
	}
	evaluator, _ := New(map[string]Enrollment{"native": a.Enrollment()})
	predicate := nativePredicate()
	predicate.Inputs = inputs
	result, err := evaluator.Evaluate(ctx, p, predicate, nil)
	if err != nil || result.Truth != Unknown || len(result.Evidence) != 0 {
		t.Fatalf("stale birth became verified outcome %+v %v", result, err)
	}
}

func TestNativePredicateRejectsPartialOrMalformedProcessBeforeRead(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	reads := 0
	a, _ := NewNative(func(context.Context, auth.Principal, model.Selector, string) (model.Value, NativeEvidence, error) {
		reads++
		return model.Value{}, NativeEvidence{}, nil
	})
	for _, change := range []func(map[string]model.Value){
		func(v map[string]model.Value) { delete(v, "processId") },
		func(v map[string]model.Value) { delete(v, "processStartToken") },
		func(v map[string]model.Value) { v["processId"] = model.Value{Kind: model.NumberValue, Number: 0} },
		func(v map[string]model.Value) {
			v["processId"] = model.Value{Kind: model.NumberValue, Number: 2147483648}
		},
		func(v map[string]model.Value) { v["processId"] = model.Value{Kind: model.StringValue, String: "42"} },
		func(v map[string]model.Value) {
			v["processStartToken"] = model.Value{Kind: model.StringValue, String: ""}
		},
		func(v map[string]model.Value) {
			v["processStartToken"] = model.Value{Kind: model.StringValue, String: "1:01"}
		},
	} {
		inputs := nativeInputs()
		inputs["processId"] = model.Value{Kind: model.NumberValue, Number: 42}
		inputs["processStartToken"] = model.Value{Kind: model.StringValue, String: "1790000000:1"}
		change(inputs)
		if _, err := a.Evaluate(ctx, p, "valueEquals", inputs); err == nil {
			t.Fatalf("invalid process reached read %+v", inputs)
		}
	}
	if reads != 0 {
		t.Fatal("invalid process identity reached callback")
	}
}

func TestNativePredicateScopedRootDeliveredToTargetAndAncestor(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	for _, root := range []string{"menuBar", "focusedElement"} {
		t.Run(root, func(t *testing.T) {
			reads := 0
			adapter, _ := NewNative(func(_ context.Context, _ auth.Principal, target model.Selector, attribute string) (model.Value, NativeEvidence, error) {
				reads++
				if target.Scope.NativeRoot != root || len(target.Scope.Window) != 0 || len(target.Scope.Frame) != 0 || target.Ancestor == nil || target.Ancestor.Scope.NativeRoot != root || target.Ancestor.Surface != target.Surface || target.Ancestor.Locator.Value.String != "exact-parent" || target.Locator.Value.String != "display" || attribute != "enabled" {
					t.Fatalf("scoped selector changed: %+v", target)
				}
				if err := target.Validate(); err != nil {
					t.Fatal(err)
				}
				return model.Value{Kind: model.BoolValue, Bool: true}, NativeEvidence{HelperEpoch: "helper", TargetRef: "scoped-ref", ObservedAt: time.Now()}, nil
			})
			inputs := nativeInputs()
			inputs["nativeRoot"] = model.Value{Kind: model.StringValue, String: root}
			inputs["ancestorID"] = model.Value{Kind: model.StringValue, String: "exact-parent"}
			inputs["attribute"] = model.Value{Kind: model.StringValue, String: "enabled"}
			inputs["expected"] = model.Value{Kind: model.BoolValue, Bool: true}
			result, err := adapter.Evaluate(ctx, p, "valueEquals", inputs)
			if err != nil || reads != 1 || result.Truth != True || result.Authority != Observational || RequireBusinessSuccess(result) == nil {
				t.Fatalf("scoped evidence: %+v reads=%d err=%v", result, reads, err)
			}
		})
	}
}

func TestNativePredicateRejectsInvalidOrMixedRootBeforeReader(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	reads := 0
	adapter, _ := NewNative(func(context.Context, auth.Principal, model.Selector, string) (model.Value, NativeEvidence, error) {
		reads++
		return model.Value{}, NativeEvidence{}, nil
	})
	for _, value := range []model.Value{{Kind: model.StringValue, String: ""}, {Kind: model.StringValue, String: "application"}, {Kind: model.StringValue, String: "menuBar "}, {Kind: model.StringValue, String: "web"}, {Kind: model.StringValue, String: "document"}, {Kind: model.NumberValue, Number: 1}, {Kind: model.BoolValue, Bool: true}, {Kind: model.StringValue, String: "menuBar", Ref: "input.root"}} {
		inputs := nativeInputs()
		inputs["nativeRoot"] = value
		if _, err := adapter.Evaluate(ctx, p, "valueEquals", inputs); err == nil {
			t.Fatal("invalid root reached reader")
		}
	}
	for _, root := range []string{"menuBar", "focusedElement"} {
		for _, window := range []string{"windowTitle", "windowRole"} {
			inputs := nativeInputs()
			inputs["nativeRoot"] = model.Value{Kind: model.StringValue, String: root}
			inputs[window] = model.Value{Kind: model.StringValue, String: "AXWindow"}
			if _, err := adapter.Evaluate(ctx, p, "valueEquals", inputs); err == nil {
				t.Fatal("mixed root/window admitted")
			}
		}
	}
	inputs := nativeInputs()
	inputs["nativeRoot"] = model.Value{Kind: model.StringValue, String: "focusedElement"}
	inputs["origin"] = model.Value{Kind: model.StringValue, String: "https://fixture.test"}
	if _, err := adapter.Evaluate(ctx, p, "valueEquals", inputs); err == nil {
		t.Fatal("web input admitted into native root")
	}
	if reads != 0 {
		t.Fatal("invalid roots invoked reader", reads)
	}
}

func TestNativePredicateScopedReadFailureNeverFallsBackToWholeApplication(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", nil)
	ctx := auth.WithPrincipal(context.Background(), p)
	reads := 0
	unavailable := &model.MechanizeError{Code: "rootUnavailable", Stage: "native", DispatchState: "notDispatched"}
	adapter, _ := NewNative(func(_ context.Context, _ auth.Principal, target model.Selector, _ string) (model.Value, NativeEvidence, error) {
		reads++
		if target.Scope.NativeRoot != "focusedElement" {
			t.Fatal("read widened to whole app")
		}
		return model.Value{}, NativeEvidence{}, unavailable
	})
	inputs := nativeInputs()
	inputs["nativeRoot"] = model.Value{Kind: model.StringValue, String: "focusedElement"}
	if _, err := adapter.Evaluate(ctx, p, "valueEquals", inputs); !errors.Is(err, unavailable) || reads != 1 {
		t.Fatal("scoped failure retried or widened", err, reads)
	}
}
