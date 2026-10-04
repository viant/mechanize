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

type replacementFixture struct {
	keyboardFixture
	mode      string
	sets      int
	cancel    context.CancelFunc
	requested bool
}

func (f *replacementFixture) Call(ctx context.Context, r Request) (Reply, error) {
	if r.Method != "elements.setValue" {
		return f.keyboardFixture.Call(ctx, r)
	}
	f.sets++
	var params map[string]any
	json.Unmarshal(r.Params, &params)
	f.requested = params["verifyReplacement"] == true
	ref := "target"
	birth := "100:1"
	generation := uint64(1)
	matched := true
	observed := time.Now()
	request := r.RequestID
	switch f.mode {
	case "target":
		ref = "foreign"
	case "birth":
		birth = "100:2"
	case "generation":
		generation = 2
	case "mismatch":
		matched = false
	case "stale":
		observed = observed.Add(-time.Minute)
	case "future":
		observed = observed.Add(time.Minute)
	case "request":
		request = "foreign"
	case "cancel":
		f.cancel()
	}
	proof, _ := json.Marshal(map[string]any{"replacementMatches": matched, "pid": 1, "startToken": birth, "bundleID": "fixture.app", "targetRef": ref, "generation": generation, "requestId": request, "observedAt": observed, "value": "fixture-private-path", "values": map[string]any{"value": "fixture-private-path"}})
	return Reply{HelperEpoch: "fixture", RequestID: r.RequestID, Result: proof, Receipt: &Receipt{DispatchState: "dispatched", TargetRef: "target"}}, nil
}
func replacementGateway(t *testing.T, f *replacementFixture) *Gateway {
	t.Helper()
	g, e := NewGateway(f, GatewayOptions{AllowedBundles: []string{"fixture.app"}, Lease: func(context.Context, auth.Principal) (Lease, error) { return Lease{ID: "fixture", Generation: 1}, nil }})
	if e != nil {
		t.Fatal(e)
	}
	return g
}
func TestReplacementBooleanProofBoundAndNoValueExport(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, mode := range []string{"", "target", "birth", "generation", "mismatch", "stale", "future", "request", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			local, cancel := context.WithCancel(ctx)
			defer cancel()
			f := &replacementFixture{mode: mode, cancel: cancel, keyboardFixture: keyboardFixture{gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "target", "nativeRole": "AXTextField", "identifier": "save", "name": "Path", "enabled": true, "value": "fixture-private-path"}}}}}
			g := replacementGateway(t, f)
			step := nativeStep("element.fill")
			step.Target.Surface.ProcessID = 1
			step.Target.Surface.ProcessStartToken = "100:1"
			step.Arguments = map[string]model.Value{"value": {Kind: model.StringValue, String: "fixture-private-path"}}
			r, e := g.Execute(local, p, step, nil)
			if e != nil {
				t.Fatal(e)
			}
			if f.sets != 1 {
				t.Fatal("replacement repeated")
			}
			want := "unknown"
			if mode == "" {
				want = "verified"
			}
			if r.VerificationState != want {
				t.Fatalf("proof %s accepted incorrectly: %s", mode, r.VerificationState)
			}
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), "fixture-private-path") || r.Value != nil {
				t.Fatal("replacement proof leaked editable value to observation/output")
			}
		})
	}
}
func TestProtectedAndBoundInputsCannotRequestReplacementComparison(t *testing.T) {
	ctx, p := nativeActor(t)
	for _, protected := range []bool{false, true} {
		f := &replacementFixture{keyboardFixture: keyboardFixture{gatewayFixture: gatewayFixture{complete: true, nodes: []map[string]any{{"ref": "target", "nativeRole": "AXTextField", "identifier": "save", "name": "Path", "enabled": true}}}}}
		g := replacementGateway(t, f)
		step := nativeStep("element.fill")
		step.Target.Surface.ProcessID = 1
		step.Target.Surface.ProcessStartToken = "100:1"
		step.Arguments = map[string]model.Value{"value": {Kind: model.ReferenceValue, Expected: model.StringValue, Ref: "input.path"}}
		if protected {
			step.Target.Locator.Value.String = "password"
			f.nodes[0]["identifier"] = "password"
			step.Arguments["value"] = model.Value{Kind: model.StringValue, String: "private-input"}
		}
		r, e := g.Execute(ctx, p, step, map[string]model.Value{"input.path": {Kind: model.StringValue, String: "private-input"}})
		if e != nil {
			t.Fatal(e)
		}
		if f.requested || r.VerificationState != "unknown" || f.sets != 1 {
			t.Fatal("protected/bound input became a comparison oracle")
		}
	}
}
