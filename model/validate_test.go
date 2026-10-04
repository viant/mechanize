package model

import "testing"

func TestTypedResolution(t *testing.T) {
	v := Value{Kind: ObjectValue, Object: map[string]Value{"items": {Kind: ArrayValue, Array: []Value{{Kind: ReferenceValue, Ref: "input.payload"}}}}}
	resolved, err := ResolveValue(v, map[string]Value{"input.payload": {Kind: StringValue, String: "${unsafe}\n\"literal\""}})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Object["items"].Array[0].String != "${unsafe}\n\"literal\"" {
		t.Fatal("value transformed")
	}
	if v.Object["items"].Array[0].Kind != ReferenceValue {
		t.Fatal("source mutated")
	}
	if _, err = ResolveValue(Value{Kind: ReferenceValue, Ref: "input.a"}, map[string]Value{"input.a": {Kind: ReferenceValue, Ref: "input.a"}}); err == nil {
		t.Fatal("cycle accepted")
	}
}
func TestTaggedValueMismatch(t *testing.T) {
	if err := (Value{Kind: StringValue, String: "hello", Ref: "input.secret"}).Validate(); err == nil {
		t.Fatal("mismatched union fields accepted")
	}
}
func TestRuntimeExpectedTypesAndCompositeCycles(t *testing.T) {
	ref := Value{Kind: ReferenceValue, Ref: "input.x", Expected: StringValue}
	if _, err := ResolveValue(ref, map[string]Value{"input.x": {Kind: NumberValue, Number: 5}}); err == nil {
		t.Fatal("wrong runtime type accepted")
	}
	cycle := Value{Kind: ObjectValue, Object: map[string]Value{"self": {Kind: ReferenceValue, Ref: "input.x"}}}
	if _, err := ResolveValue(ref, map[string]Value{"input.x": cycle}); err == nil {
		t.Fatal("composite cycle accepted")
	}
	s := Step{Action: "element.fill", Arguments: map[string]Value{"value": {Kind: ReferenceValue, Ref: "input.x"}}}
	if _, err := s.ResolveArguments(map[string]Value{"input.x": {Kind: BoolValue, Bool: true}}); err == nil {
		t.Fatal("action type mismatch accepted")
	}
}
func TestRecursiveSelectorLimit(t *testing.T) {
	s := Selector{Surface: Surface{Kind: "native", BundleID: "fixture"}, Cardinality: "one"}
	s.Ancestor = &s
	if err := s.Validate(); err == nil {
		t.Fatal("cyclic selector accepted")
	}
}
