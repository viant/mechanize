package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/model"
	"testing"
)

type focusedReadFixture struct {
	keyboardFixture
	state   *bool
	methods []string
}

func (f *focusedReadFixture) Call(ctx context.Context, r Request) (Reply, error) {
	f.methods = append(f.methods, r.Method)
	if r.Method == "elements.read" {
		values := map[string]any{}
		unavailable := []string{}
		if f.state != nil {
			values["focused"] = *f.state
		} else {
			unavailable = append(unavailable, "focused")
		}
		b, _ := json.Marshal(map[string]any{"values": values, "unavailable": unavailable})
		return Reply{HelperEpoch: "fixture", Result: b}, nil
	}
	return f.keyboardFixture.Call(ctx, r)
}
func TestFocusedReadIsBooleanReadOnlyAndErrorsNeverBecomeFalse(t *testing.T) {
	ctx, p := nativeActor(t)
	yes, no := true, false
	for _, state := range []*bool{&yes, &no, nil} {
		f := &focusedReadFixture{state: state, keyboardFixture: keyboardFixture{gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "target", "nativeRole": "AXCheckBox", "identifier": "save", "enabled": true}}}}}
		g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
		step := nativeStep("element.read")
		step.Effect.Class = model.ReadOnly
		step.Target.Surface.ProcessID = 1
		step.Target.Surface.ProcessStartToken = "100:1"
		step.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: "focused"}}
		result, err := g.Execute(ctx, p, step, nil)
		if state == nil {
			if err == nil || result.Value != nil {
				t.Fatal("unavailable focus guessed false")
			}
		} else if err != nil || result.Value == nil || result.Value.Kind != model.BoolValue || result.Value.Bool != *state {
			t.Fatal("focus boolean not retained")
		}
		for _, method := range f.methods {
			if method == "elements.focus" || method == "elements.pressKey" || method == "lease.install" {
				t.Fatal("focus read dispatched input or acquired keyboard authority")
			}
		}
	}
}
