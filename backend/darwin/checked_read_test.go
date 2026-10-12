package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/model"
	"testing"
)

type checkedReadFixture struct {
	gatewayFixture
	advertised bool
	raw        string
	reads      int
}

func (f *checkedReadFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if r.Method == "doctor" {
		names := []string{}
		if f.advertised {
			names = append(names, "checked")
		}
		b, _ := json.Marshal(map[string]any{"axTrusted": true, "nativeBooleanReads": names})
		return Reply{HelperEpoch: "fixture", Result: b}, nil
	}
	if r.Method == "elements.read" {
		f.reads++
		return Reply{HelperEpoch: "fixture", Result: json.RawMessage(`{"values":{"checked":` + f.raw + `}}`)}, nil
	}
	return f.gatewayFixture.Call(ctx, r)
}
func TestCheckedReadRequiresCapabilityRoleAndExactBoolean(t *testing.T) {
	for _, tc := range []struct {
		name, role, raw          string
		advertised, wantOK, want bool
	}{
		{"checked", "AXCheckBox", "true", true, true, true},
		{"unchecked", "AXRadioButton", "false", true, true, false},
		{"mixed", "AXCheckBox", "2", true, false, false},
		{"null", "AXCheckBox", "null", true, false, false},
		{"string", "AXCheckBox", `"false"`, true, false, false},
		{"wrong role", "AXButton", "true", true, false, false},
		{"old helper", "AXCheckBox", "true", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, p := nativeActor(t)
			f := &checkedReadFixture{advertised: tc.advertised, raw: tc.raw, gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "target", "identifier": "save", "nativeRole": tc.role}}}}
			g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
			s := nativeStep("element.read")
			s.Effect.Class = model.ReadOnly
			s.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: "checked"}}
			r, err := g.Execute(ctx, p, s, nil)
			if tc.wantOK {
				if err != nil || r.Value == nil || r.Value.Kind != model.BoolValue || r.Value.Bool != tc.want {
					t.Fatalf("read %+v %v", r, err)
				}
			} else if err == nil || r.Value != nil {
				t.Fatalf("unknown state accepted: %+v", r)
			}
			if (!tc.advertised || tc.role == "AXButton") && f.reads != 0 {
				t.Fatal("unqualified read reached helper")
			}
			for _, method := range f.calls {
				if method == "lease.install" || method == "elements.press" {
					t.Fatal("read acquired input authority")
				}
			}
		})
	}
}
func TestCheckedAssertionSupportsNegation(t *testing.T) {
	ctx, p := nativeActor(t)
	f := &checkedReadFixture{advertised: true, raw: "false", gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "target", "identifier": "save", "nativeRole": "AXCheckBox"}}}}
	g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	for _, negated := range []bool{false, true} {
		s := nativeStep("expect")
		s.Effect.Class = model.ReadOnly
		s.Assertion = &model.Assertion{Matcher: "toBeChecked", Not: negated}
		_, err := g.Execute(ctx, p, s, nil)
		if (err == nil) != negated {
			t.Fatalf("false checkbox negated=%v: %v", negated, err)
		}
	}
	// A refreshed doctor must not retain a capability omitted by its replacement.
	f.advertised = false
	g.epoch = ""
	if err := g.ready(ctx); err != nil {
		t.Fatal(err)
	}
	if g.checkedReadEnabled {
		t.Fatal("stale checkbox capability retained")
	}
}
