package darwin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/viant/mechanize/model"
)

type staticTextFixture struct {
	gatewayFixture
	text       string
	readParams map[string]any
}

func (f *staticTextFixture) Call(ctx context.Context, request Request) (Reply, error) {
	reply, err := f.gatewayFixture.Call(ctx, request)
	if request.Method == "elements.read" {
		_ = json.Unmarshal(request.Params, &f.readParams)
		reply.Result, _ = json.Marshal(map[string]any{"values": map[string]any{"staticText": f.text}})
	}
	return reply, err
}

func TestStaticTextReadPolicyFreshUniqueAndBounded(t *testing.T) {
	ctx, principal := nativeActor(t)
	node := map[string]any{"ref": "display", "nativeRole": "AXStaticText"}
	for _, tc := range []struct {
		name      string
		allowed   bool
		nodes     []map[string]any
		complete  bool
		text      string
		read      bool
		wantError bool
	}{
		{"optIn", true, []map[string]any{node}, true, "391", true, false},
		{"defaultDenied", false, []map[string]any{node}, true, "391", false, true},
		{"duplicate", true, []map[string]any{node, node}, true, "391", false, true},
		{"partial", true, []map[string]any{node}, false, "391", false, true},
		{"editableRole", true, []map[string]any{{"ref": "display", "nativeRole": "AXTextField"}}, true, "391", false, true},
		{"oversized", true, []map[string]any{node}, true, string(make([]byte, 4097)), true, true},
		{"nul", true, []map[string]any{node}, true, "391\x00", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := &staticTextFixture{gatewayFixture: gatewayFixture{nodes: tc.nodes, complete: tc.complete}, text: tc.text}
			options := GatewayOptions{AllowedBundles: []string{"fixture.app"}}
			if tc.allowed {
				options.AllowedStaticTextBundles = []string{"fixture.app"}
			}
			gateway, err := NewGateway(fixture, options)
			if err != nil {
				t.Fatal(err)
			}
			step := nativeStep("element.read")
			step.Effect.Class = model.ReadOnly
			step.Target.Locator.Strategy = "role"
			step.Target.Locator.Value.String = "AXStaticText"
			if tc.name == "editableRole" {
				step.Target.Locator.Value.String = "textbox"
			}
			step.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: "staticText"}}
			result, err := gateway.Execute(ctx, principal, step, nil)
			if (err != nil) != tc.wantError {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if (fixture.readParams != nil) != tc.read {
				t.Fatalf("unexpected read: %+v", fixture.readParams)
			}
			if tc.read && (fixture.readParams["allowStaticTextRead"] != true || fixture.readParams["elementRef"] != "display" || fixture.readParams["expectedApp"] != "fixture.app") {
				t.Fatalf("unscoped read: %+v", fixture.readParams)
			}
			if !tc.wantError && (result.Value == nil || result.Value.String != "391" || result.VerificationState != "verified") {
				t.Fatalf("missing verified read: %+v", result)
			}
			if !tc.wantError {
				fixture.text = "392"
				result, err = gateway.Execute(ctx, principal, step, nil)
				if err != nil || result.Value == nil || result.Value.String != "392" {
					t.Fatalf("read reused old evidence: %+v %v", result, err)
				}
				snapshots := 0
				for _, call := range fixture.calls {
					if call == "elements.snapshot" {
						snapshots++
					}
				}
				if snapshots != 2 {
					t.Fatalf("expected fresh resolution for each read, snapshots=%d", snapshots)
				}
			}
		})
	}
}

func TestStaticTextPolicyRejectsScopeAndWildcard(t *testing.T) {
	for _, bundle := range []string{"other.app", "*", "fixture.*", ""} {
		if _, err := NewGateway(&gatewayFixture{}, GatewayOptions{AllowedBundles: []string{"fixture.app"}, AllowedStaticTextBundles: []string{bundle}}); err == nil {
			t.Fatalf("policy admitted %q", bundle)
		}
	}
	if _, err := NewGateway(&gatewayFixture{}, GatewayOptions{AllowedBundles: []string{"fixture.app"}, AllowedStaticTextBundles: []string{"fixture.app", "fixture.app"}}); err == nil {
		t.Fatal("duplicate static text policy admitted")
	}
}
