package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/model"
	"testing"
)

type textSelectionFixture struct {
	gatewayFixture
	advertised  bool
	raw         string
	unavailable bool
	reads       int
}

func (f *textSelectionFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if r.Method == "doctor" {
		names := []string{}
		if f.advertised {
			names = append(names, "hasFullTextSelection")
		}
		raw, _ := json.Marshal(map[string]any{"axTrusted": true, "nativeBooleanReads": names})
		return Reply{HelperEpoch: "fixture", Result: raw}, nil
	}
	if r.Method == "elements.read" {
		f.reads++
		suffix := ""
		if f.unavailable {
			suffix = `,"unavailable":["hasFullTextSelection"]`
		}
		return Reply{HelperEpoch: "fixture", Result: json.RawMessage(`{"values":{"hasFullTextSelection":` + f.raw + `}` + suffix + `}`)}, nil
	}
	return f.gatewayFixture.Call(ctx, r)
}
func TestTextSelectionReadRequiresQualifiedBooleanWithoutInput(t *testing.T) {
	for _, tc := range []struct {
		raw, role                             string
		advertised, unavailable, wantOK, want bool
	}{
		{"true", "AXTextArea", true, false, true, true}, {"false", "AXTextField", true, false, true, false}, {"null", "AXTextArea", true, false, false, false}, {`"true"`, "AXTextArea", true, false, false, false}, {"1", "AXTextArea", true, false, false, false}, {"true", "AXButton", true, false, false, false}, {"true", "AXTextArea", false, false, false, false}, {"true", "AXTextArea", true, true, false, false},
	} {
		f := &textSelectionFixture{advertised: tc.advertised, raw: tc.raw, unavailable: tc.unavailable, gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "field", "identifier": "save", "nativeRole": tc.role}}}}
		g, _ := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
		ctx, p := nativeActor(t)
		step := nativeStep("element.read")
		step.Effect.Class = model.ReadOnly
		step.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: "hasFullTextSelection"}}
		result, err := g.Execute(ctx, p, step, nil)
		if tc.wantOK {
			if err != nil || result.Value == nil || result.Value.Kind != model.BoolValue || result.Value.Bool != tc.want {
				t.Fatal("valid selection lost", err)
			}
		} else if err == nil || result.Value != nil {
			t.Fatal("unavailable selection accepted")
		}
		if (!tc.advertised || tc.role == "AXButton") && f.reads != 0 {
			t.Fatal("unqualified read reached helper")
		}
		for _, method := range f.calls {
			if method == "lease.install" || method == "elements.setValue" {
				t.Fatal("selection read acquired input")
			}
		}
	}
}
