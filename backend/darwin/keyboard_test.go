package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
)

type keyboardFixture struct {
	foreignFocus bool
	gatewayFixture
	keyboard bool
	requests []Request
}

func (f *keyboardFixture) Call(ctx context.Context, r Request) (Reply, error) {
	f.requests = append(f.requests, r)
	switch r.Method {
	case "doctor":
		b, _ := json.Marshal(map[string]any{"axTrusted": true, "semanticEnabled": true, "targetedKeyboardEnabled": f.keyboard})
		return Reply{HelperEpoch: "fixture", Result: b}, nil
	case "apps.list":
		return Reply{HelperEpoch: "fixture", Result: json.RawMessage(`{"complete":true,"apps":[{"pid":1,"bundleID":"fixture.app","launchTime":"launch","startToken":"100:1"}]}`)}, nil
	case "elements.focus":
		birth := "100:1"
		if f.foreignFocus {
			birth = "100:2"
		}
		proof, _ := json.Marshal(map[string]any{"focused": true, "pid": 1, "startToken": birth, "bundleID": "fixture.app", "targetRef": "target", "generation": 1})
		return Reply{HelperEpoch: "fixture", Result: proof, Receipt: &Receipt{DispatchState: "dispatched", TargetRef: "target"}}, nil
	case "elements.pressKey":
		return Reply{HelperEpoch: "fixture", Receipt: &Receipt{DispatchState: "dispatched", TargetRef: "target"}}, nil
	}
	return f.gatewayFixture.Call(ctx, r)
}
func TestTargetedKeyboardAndExplicitFocusUseTypedScopedRoute(t *testing.T) {
	ctx, p := nativeActor(t)
	f := &keyboardFixture{keyboard: true, gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "target", "nativeRole": "AXCheckBox", "identifier": "save", "enabled": true, "focused": true, "focusSettable": true, "actions": []string{}, "valueSettable": false}}}}
	g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) {
		return Lease{ID: "fixture-lease", Generation: 1}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"element.focus", "element.pressKey"} {
		step := nativeStep(action)
		step.Target.Surface.ProcessID = 1
		step.Target.Surface.ProcessStartToken = "100:1"
		if action == "element.pressKey" {
			step.Arguments = map[string]model.Value{"key": {Kind: model.StringValue, String: "Cmd+Shift+G"}}
		}
		result, err := g.Execute(ctx, p, step, nil)
		if action == "element.focus" && result.VerificationState != "verified" {
			t.Fatal("exact independently verified focus receipt not adopted")
		}
		if err != nil || result.DispatchState != "dispatched" {
			t.Fatalf("typed %s: %+v %v", action, result, err)
		}
	}
	keys := 0
	for _, request := range f.requests {
		if strings.HasPrefix(request.Method, "input.") {
			t.Fatal("raw input route used")
		}
		if request.Method == "elements.pressKey" {
			keys++
			var params map[string]any
			json.Unmarshal(request.Params, &params)
			if params["key"] != "Cmd+Shift+G" || params["elementRef"] != "target" || request.Lease == nil {
				t.Fatal("typed chord/fresh ref/lease lost")
			}
		}
	}
	if keys != 1 {
		t.Fatal("key command replayed or absent")
	}
}
func TestKeyboardProfileAndClosedArgumentFailBeforeInput(t *testing.T) {
	for _, key := range []string{"", "keyCode:49", "Command+Command+G", "Cmd+Command+G", "Alt+G", "Cmd+Shift+G+Space"} {
		if validateKeyboardChord(key) == nil {
			t.Fatal("unclosed keyboard argument accepted")
		}
	}
	for _, key := range []string{"Space", "Tab", "Return", "Escape", "ArrowDown", "Cmd+Shift+G"} {
		if validateKeyboardChord(key) != nil {
			t.Fatal("supported named key rejected")
		}
	}
	for _, options := range []Options{{HelperPath: "/must-not-launch", AllowTargetedKeyboard: true}, {HelperPath: "/must-not-launch", AllowTargetedKeyboard: true, AllowSemantic: true, AllowMutations: true}} {
		if c, e := NewClient(context.Background(), options); e == nil || c != nil {
			t.Fatal("unscoped/ambiguous keyboard helper launched")
		}
	}
	ctx, p := nativeActor(t)
	f := &keyboardFixture{keyboard: false, gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "target", "nativeRole": "AXCheckBox", "identifier": "save", "enabled": true, "focused": true, "focusSettable": false}}}}
	g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "fixture", Generation: 1}, nil }})
	step := nativeStep("element.pressKey")
	step.Target.Surface.ProcessID = 1
	step.Target.Surface.ProcessStartToken = "100:1"
	step.Arguments = map[string]model.Value{"key": {Kind: model.StringValue, String: "Space"}}
	if r, e := g.Execute(ctx, p, step, nil); e == nil || r.DispatchState != "notDispatched" {
		t.Fatal("semantic-only profile admitted keyboard")
	}
	step = nativeStep("element.focus")
	step.Target.Surface.ProcessID = 1
	step.Target.Surface.ProcessStartToken = "100:1"
	if r, e := g.Execute(ctx, p, step, nil); e == nil || r.DispatchState != "notDispatched" {
		t.Fatal("nonsettable focus targeted")
	}
	for _, request := range f.requests {
		if request.Method == "elements.focus" || request.Method == "elements.pressKey" || strings.HasPrefix(request.Method, "input.") {
			t.Fatal("failed gate dispatched input")
		}
	}
}
func TestExplicitFocusReceiptMustMatchExactKernelBirthAndReference(t *testing.T) {
	ctx, p := nativeActor(t)
	f := &keyboardFixture{foreignFocus: true, gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "target", "nativeRole": "AXCheckBox", "identifier": "save", "enabled": true, "focusSettable": true}}}}
	g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "fixture", Generation: 1}, nil }})
	step := nativeStep("element.focus")
	step.Target.Surface.ProcessID = 1
	step.Target.Surface.ProcessStartToken = "100:1"
	r, e := g.Execute(ctx, p, step, nil)
	if e != nil || r.VerificationState != "unknown" || r.DispatchState != "dispatched" {
		t.Fatalf("foreign focus proof accepted: %+v %v", r, e)
	}
}
