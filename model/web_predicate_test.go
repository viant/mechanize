package model

import (
	"errors"
	"strings"
	"testing"
)

func webContractFixture() Predicate {
	return Predicate{Kind: "adapter", Adapter: "web", Name: "valueEquals", Scope: PredicateScope{SurfaceRef: "fixture"}, TimeoutMs: 3000, FreshnessMs: 3000, RequiredAuthority: "observational", Inputs: map[string]Value{"origin": {Kind: StringValue, String: "https://fixture.test"}, "strategy": {Kind: StringValue, String: "id"}, "selector": {Kind: StringValue, String: "message"}, "attribute": {Kind: StringValue, String: "value"}, "expected": {Kind: StringValue, String: "Public fixture"}}}
}
func TestWebPredicateContractRejectsUnsupportedShapeBeforeExecution(t *testing.T) {
	for _, mode := range []string{"id", "authority", "missing", "type", "strategy", "name", "index", "order", "large", "timeout", "valid", "reference"} {
		t.Run(mode, func(t *testing.T) {
			p := webContractFixture()
			switch mode {
			case "id":
				delete(p.Inputs, "strategy")
				delete(p.Inputs, "selector")
				p.Inputs["id"] = Value{Kind: StringValue, String: "PRIVATE_CANARY"}
			case "authority":
				p.RequiredAuthority = "authoritative"
			case "missing":
				delete(p.Inputs, "expected")
			case "type":
				p.Inputs["selector"] = Value{Kind: NumberValue, Number: 3}
			case "strategy":
				p.Inputs["strategy"] = Value{Kind: StringValue, String: "css"}
			case "name":
				p.Inputs["name"] = Value{Kind: StringValue, String: "label"}
			case "index":
				p.Inputs["index"] = Value{Kind: NumberValue, Number: 1}
			case "order":
				p.Inputs["index"] = Value{Kind: NumberValue, Number: 1}
				p.Inputs["order"] = Value{Kind: StringValue, String: "tree"}
			case "large":
				p.Inputs["expected"] = Value{Kind: StringValue, String: strings.Repeat("x", 256)}
			case "timeout":
				p.TimeoutMs = 30001
			case "reference":
				p.Inputs["expected"] = Value{Kind: ReferenceValue, Ref: "input.expected", Expected: StringValue}
			}
			e := p.Validate()
			if mode == "valid" || mode == "reference" {
				if e != nil {
					t.Fatal(e)
				}
				return
			}
			var typed *MechanizeError
			if !errors.As(e, &typed) || typed.Code != "invalidPredicate" || typed.DispatchState != "notDispatched" || typed.EffectState != "none" || strings.Contains(e.Error(), "PRIVATE_CANARY") {
				t.Fatal("missing static contract rejection", e)
			}
		})
	}
}
