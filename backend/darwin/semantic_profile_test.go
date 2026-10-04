package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"os"
	"strings"
	"testing"
)

func TestSemanticClientRequiresSignedEnrollmentFenceAndExclusiveMode(t *testing.T) {
	for _, options := range []Options{{HelperPath: "/must-not-launch", AllowSemantic: true}, {HelperPath: "/must-not-launch", AllowSemantic: true, AllowMutations: true}, {HelperPath: "/must-not-launch", AllowSemantic: true, AllowLaunch: true}} {
		if client, err := NewClient(context.Background(), options); err == nil || client != nil {
			t.Fatalf("unqualified profile %+v %v", client, err)
		}
	}
	fence, err := os.CreateTemp(t.TempDir(), "fence")
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Close()
	if client, err := NewClient(context.Background(), Options{HelperPath: "/must-not-launch", AllowSemantic: true, Fence: fence}); client != nil || err == nil || !strings.Contains(err.Error(), "enrolled") {
		t.Fatalf("unsigned semantic launch %+v %v", client, err)
	}
}

type semanticGatewayFixture struct {
	gatewayFixture
	submitSupported bool
	semanticCalls   []string
}

func (f *semanticGatewayFixture) Call(ctx context.Context, request Request) (Reply, error) {
	f.semanticCalls = append(f.semanticCalls, request.Method)
	if request.Method == "doctor" {
		return Reply{HelperEpoch: "fixture", Result: json.RawMessage(`{"axTrusted":true,"semanticEnabled":true,"mutationEnabled":false}`)}, nil
	}
	if request.Method == "elements.submit" {
		if !f.submitSupported {
			err := &NativeError{Code: "unsupported", Message: "AXConfirm not advertised", DispatchState: "notDispatched"}
			return Reply{HelperEpoch: "fixture", Receipt: &Receipt{DispatchState: "notDispatched"}}, err
		}
		return Reply{HelperEpoch: "fixture", Receipt: &Receipt{DispatchState: "dispatched"}}, nil
	}
	return f.gatewayFixture.Call(ctx, request)
}
func TestSemanticSubmitUsesOnlyAXConfirmRouteAndDoesNotVerifyReceipt(t *testing.T) {
	for _, supported := range []bool{true, false} {
		fixture := &semanticGatewayFixture{gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "search", "identifier": "save", "nativeRole": "AXTextField", "enabled": true}}}, submitSupported: supported}
		gateway, err := NewGateway(fixture, GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "desktop", Generation: 1}, nil }})
		if err != nil {
			t.Fatal(err)
		}
		ctx, p := nativeActor(t)
		step := nativeStep("element.submit")
		result, err := gateway.Execute(ctx, p, step, nil)
		if supported {
			if err != nil || result.DispatchState != "dispatched" || result.VerificationState != "unknown" {
				t.Fatalf("submit %+v %v", result, err)
			}
		} else if err == nil || result.DispatchState != "notDispatched" {
			t.Fatalf("unsupported reinterpreted %+v %v", result, err)
		}
		submits := 0
		for _, method := range fixture.semanticCalls {
			if method == "elements.submit" {
				submits++
			}
			if method == "elements.press" || strings.HasPrefix(method, "input.") {
				t.Fatalf("submit silently used %s", method)
			}
		}
		if submits != 1 {
			t.Fatalf("submit replayed %d times", submits)
		}
	}
}

func TestRoleNameUniquenessNeedsNamesOnlyOnMatchingRoles(t *testing.T) {
	name := model.Value{Kind: model.StringValue, String: "7"}
	target := model.Selector{Cardinality: "one", Locator: &model.Locator{Strategy: "role", Value: model.Value{Kind: model.StringValue, String: "button"}, Name: &name, Exact: true}}
	observation := model.Observation{Nodes: []model.Node{{Role: "menu", Unavailable: []string{"name"}}, {Role: "button", Name: "7", Identifier: "seven"}}}
	node, err := resolve(observation, target, nil)
	if err != nil || node.Identifier != "seven" {
		t.Fatalf("unrelated name blocked exactcandidate: %+v %v", node, err)
	}
	observation.Nodes = append(observation.Nodes, model.Node{Role: "button", Unavailable: []string{"name"}})
	if _, err = resolve(observation, target, nil); err == nil {
		t.Fatal("unknown candidate name manufactured uniqueness")
	}
}
