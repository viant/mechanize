package darwin

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
	"time"
)

type textFixture struct {
	keyboardFixture
	mode            string
	setters, probes int
	requested       bool
	last            map[string]any
}

func (f *textFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if e := ctx.Err(); e != nil {
		return Reply{}, e
	}
	if r.Method == "doctor" {
		actions := []string{"replaceText"}
		reads := []string{"valueMatches"}
		if f.mode == "noAction" {
			actions = nil
		}
		if f.mode == "noRead" {
			reads = nil
		}
		body, _ := json.Marshal(map[string]any{"axTrusted": true, "semanticEnabled": true, "nativeTextActions": actions, "nativeTextReads": reads})
		return Reply{HelperEpoch: "fixture", Result: body}, nil
	}
	if r.Method != "elements.replaceText" && r.Method != "elements.valueMatches" {
		return f.keyboardFixture.Call(ctx, r)
	}
	json.Unmarshal(r.Params, &f.last)
	f.requested = f.last["verifyReplacement"] == true
	observed := time.Now()
	proof := map[string]any{"pid": 1, "startToken": "100:1", "bundleID": "fixture.app", "targetRef": "target", "generation": 1, "requestId": r.RequestID, "observedAt": observed}
	reply := Reply{HelperEpoch: "fixture", RequestID: r.RequestID}
	if r.Method == "elements.replaceText" {
		f.setters++
		proof["replacementMatches"] = f.mode != "mismatch"
		reply.Receipt = &Receipt{DispatchState: "dispatched", TargetRef: "target"}
		if f.mode == "noReceipt" {
			reply.Receipt = nil
		}
		if f.mode == "selectionUnknown" {
			return reply, &NativeError{Code: "replacementUnknown", DispatchState: "unknown"}
		}
	} else {
		f.probes++
		proof["matches"] = f.mode != "false"
	}
	switch f.mode {
	case "wrongPID":
		proof["pid"] = 2
	case "wrongBirth":
		proof["startToken"] = "100:2"
	case "wrongRef":
		proof["targetRef"] = "foreign"
	case "wrongGeneration":
		proof["generation"] = 2
	case "wrongRequest":
		proof["requestId"] = "foreign"
	case "stale":
		proof["observedAt"] = observed.Add(-time.Minute)
	case "future":
		proof["observedAt"] = observed.Add(time.Minute)
	case "missingBool":
		delete(proof, "matches")
	case "extraValue":
		proof["value"] = "PRIVATE_FIELD_VALUE"
	case "wrongEpoch":
		reply.HelperEpoch = "foreign"
	}
	reply.Result, _ = json.Marshal(proof)
	return reply, nil
}
func textGateway(t *testing.T, mode string) (*Gateway, *textFixture) {
	t.Helper()
	node := map[string]any{"ref": "target", "nativeRole": "AXTextField", "identifier": "save", "name": "Path", "enabled": true, "selectedTextSettable": true, "selectedTextRangeSettable": true}
	if mode == "noRange" {
		delete(node, "selectedTextRangeSettable")
	}
	if mode == "noSelectedText" {
		node["selectedTextSettable"] = false
	}
	nodes := []map[string]any{node}
	if mode == "duplicate" {
		second := map[string]any{"ref": "second", "nativeRole": "AXTextField", "identifier": "save", "enabled": true}
		nodes = append(nodes, second)
	}
	f := &textFixture{mode: mode, keyboardFixture: keyboardFixture{gatewayFixture: gatewayFixture{complete: mode != "partial", nodes: nodes}}}
	g, e := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "held", Generation: 1}, nil }})
	if e != nil {
		t.Fatal(e)
	}
	return g, f
}
func textStep() model.Step {
	s := nativeStep("element.replaceText")
	s.Target.Surface.ProcessID = 1
	s.Target.Surface.ProcessStartToken = "100:1"
	s.Arguments = map[string]model.Value{"value": {Kind: model.StringValue, String: "nonsecret literal"}}
	return s
}
func TestReplaceTextExplicitSetterLiteralProofAndNoFallback(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, mode := range []string{"valid", "noAction", "noRange", "noSelectedText", "partial", "duplicate", "mismatch", "wrongPID", "wrongBirth", "wrongRef", "wrongGeneration", "wrongRequest", "stale", "future", "noReceipt", "selectionUnknown"} {
		t.Run(mode, func(t *testing.T) {
			g, f := textGateway(t, mode)
			r, e := g.Execute(ctx, p, textStep(), nil)
			pre := mode == "noAction" || mode == "noRange" || mode == "noSelectedText" || mode == "partial" || mode == "duplicate"
			if pre {
				if e == nil || f.setters != 0 || r.DispatchState != "notDispatched" {
					t.Fatal("unqualified replacement dispatched", r, e)
				}
			} else {
				if f.setters != 1 {
					t.Fatal("setter not exactlyonce", f.setters)
				}
				if mode == "valid" {
					if e != nil || r.VerificationState != "verified" {
						t.Fatal("literal proof not verified", r, e)
					}
				} else if r.VerificationState == "verified" {
					t.Fatal("invalid proof verified", r)
				}
			}
			for _, request := range f.requests {
				if request.Method == "elements.setValue" || strings.HasPrefix(request.Method, "input.") {
					t.Fatal("replacement usedfallback", request.Method)
				}
			}
		})
	}
}
func TestReplaceTextReferencesDoNotEnableAutomaticValueOracle(t *testing.T) {
	ctx, p := nativeActor(t)
	g, f := textGateway(t, "valid")
	s := textStep()
	s.Arguments["value"] = model.Value{Kind: model.ReferenceValue, Expected: model.StringValue, Ref: "input.path"}
	r, e := g.Execute(ctx, p, s, map[string]model.Value{"input.path": {Kind: model.StringValue, String: "PRIVATE_VALUE"}})
	if e != nil || f.requested || r.VerificationState == "verified" {
		t.Fatal("reference becamebooleanoracle", r, e)
	}
	body, _ := json.Marshal(r)
	if strings.Contains(string(body), "PRIVATE_VALUE") {
		t.Fatal("value exported")
	}
}
func TestValueMatchesReturnsAuthenticatedBooleanMetadataOnly(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, mode := range []string{"valid", "false", "noRead", "partial", "duplicate", "wrongPID", "wrongBirth", "wrongRef", "wrongGeneration", "wrongRequest", "stale", "future", "missingBool", "extraValue", "wrongEpoch"} {
		t.Run(mode, func(t *testing.T) {
			g, f := textGateway(t, mode)
			proof, e := g.ValueMatches(ctx, p, textStep().Target, "expected literal")
			if mode == "valid" || mode == "false" {
				if e != nil || proof.Matches != (mode == "valid") || proof.HelperEpoch != "fixture" || proof.TargetRef != "target" || proof.ObservedAt.IsZero() {
					t.Fatal("boolean metadata invalid", proof, e)
				}
				if f.last["expected"] != "expected literal" {
					t.Fatal("expectedchanged")
				}
			} else if e == nil {
				t.Fatal("invalid proof becameboolean", proof)
			}
			for _, request := range f.requests {
				if request.Lease != nil || request.Method == "elements.read" || strings.HasPrefix(request.Method, "input.") {
					t.Fatal("private comparison usedread/inputfallback", request.Method)
				}
			}
		})
	}
}
func TestValueMatchesRejectsProtectedOrUnownedComparison(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, mode := range []string{"protected", "unowned", "observeOnly", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			g, f := textGateway(t, "valid")
			target := textStep().Target
			expected := "literal"
			local := ctx
			actor := p
			switch mode {
			case "protected":
				target.Locator.Value.String = "password"
			case "unowned":
				local = context.Background()
			case "observeOnly":
				actor.Scopes = []string{"desktop:observe"}
				local = auth.WithPrincipal(local, actor)
			case "oversize":
				expected = strings.Repeat("x", 65537)
			}
			if _, e := g.ValueMatches(local, actor, target, expected); e == nil || f.probes != 0 {
				t.Fatal("protected/unowned comparison reachedgetter", e, f.probes)
			}
		})
	}
}
