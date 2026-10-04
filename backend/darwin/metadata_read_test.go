package darwin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/viant/mechanize/model"
)

type metadataReadFixture struct {
	gatewayFixture
	reads int
}

func (f *metadataReadFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if r.Method == "elements.read" {
		f.reads++
		return Reply{HelperEpoch: "fixture", Result: json.RawMessage(`{"values":{"identifier":"save","role":"AXButton","enabled":true}}`)}, nil
	}
	return f.gatewayFixture.Call(ctx, r)
}

func TestNativeEnabledReadReachesHelperAsBoolean(t *testing.T) {
	ctx, p := nativeActor(t)
	f := &metadataReadFixture{gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "target", "identifier": "save", "nativeRole": "AXButton"}}}}
	g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	if err != nil {
		t.Fatal(err)
	}
	s := nativeStep("element.read")
	s.Effect.Class = model.ReadOnly
	s.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: "enabled"}}
	r, err := g.Execute(ctx, p, s, nil)
	if err != nil || r.Value == nil || r.Value.Kind != model.BoolValue || !r.Value.Bool || f.reads != 1 {
		t.Fatalf("enabled metadata %+v %v", r, err)
	}
}
func TestNativeMetadataReadPassesSharedValidationAndHelper(t *testing.T) {
	ctx, p := nativeActor(t)
	f := &metadataReadFixture{gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "target", "identifier": "save", "nativeRole": "AXButton"}}}}
	g, err := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	if err != nil {
		t.Fatal(err)
	}
	for attribute, want := range map[string]string{"identifier": "save", "role": "AXButton"} {
		s := nativeStep("element.read")
		s.Effect.Class = model.ReadOnly
		s.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: attribute}}
		r, err := g.Execute(ctx, p, s, nil)
		if err != nil || r.Value == nil || r.Value.String != want || r.VerificationState != "verified" || r.Observation == nil {
			t.Fatalf("metadata read %+v %v", r, err)
		}
	}
	if f.reads != 2 {
		t.Fatal("reads did not reach helper")
	}
}
