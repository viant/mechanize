package model

import "testing"

func TestNativeProcessIdentityClosedFingerprint(t *testing.T) {
	for _, s := range []Surface{{Kind: "native"}, {Kind: "native", ProcessID: 42, ProcessStartToken: "1790000000:0"}} {
		if err := s.ValidateProcessIdentity(); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []Surface{{Kind: "native", ProcessID: 42}, {Kind: "native", ProcessStartToken: "1790000000:0"}, {Kind: "web", ProcessID: 42, ProcessStartToken: "1790000000:0"}, {Kind: "native", ProcessID: -1, ProcessStartToken: "1790000000:0"}} {
		if s.ValidateProcessIdentity() == nil {
			t.Fatalf("accepted incomplete/cross-surface identity: %+v", s)
		}
	}
	for _, token := range []string{"start", "0:1", "1:01", "1:1000000", "1:1\n", "18446744073709551616:1", "-1:0"} {
		if ValidProcessStartToken(token) {
			t.Fatalf("accepted invalid token %q", token)
		}
	}
}

func TestNativePredicateProcessPairing(t *testing.T) {
	p := Predicate{Kind: "adapter", Adapter: "native", Name: "valueEquals", Scope: PredicateScope{SurfaceRef: "chrome"}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "observational", Inputs: map[string]Value{"processId": {Kind: NumberValue, Number: 42}, "processStartToken": {Kind: StringValue, String: "1790000000:1"}}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []map[string]Value{
		{"processId": {Kind: NumberValue, Number: 42}},
		{"processStartToken": {Kind: StringValue, String: "1790000000:1"}},
		{"processId": {Kind: NumberValue, Number: 0}, "processStartToken": {Kind: StringValue, String: "1790000000:1"}},
		{"processId": {Kind: NumberValue, Number: 42}, "processStartToken": {Kind: StringValue, String: "start"}},
		{"processId": {Kind: ReferenceValue, Ref: "input.pid", Expected: StringValue}, "processStartToken": {Kind: StringValue, String: "1790000000:1"}},
	} {
		p.Inputs = invalid
		if p.Validate() == nil {
			t.Fatalf("invalid native process accepted %+v", invalid)
		}
	}
	p.Inputs = map[string]Value{"processId": {Kind: ReferenceValue, Ref: "input.pid", Expected: NumberValue}, "processStartToken": {Kind: ReferenceValue, Ref: "input.start", Expected: StringValue}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Adapter = "other"
	p.Inputs = map[string]Value{"processId": {Kind: StringValue, String: "external-contract"}}
	if err := p.Validate(); err != nil {
		t.Fatalf("generic adapter contract changed: %v", err)
	}
}
