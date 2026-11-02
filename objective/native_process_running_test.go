package objective

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestNativeProcessRunningPreservesUnknownAndAuthorization(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "alice", []string{"desktop:observe"})
	ctx := auth.WithPrincipal(context.Background(), p)
	inputs := map[string]model.Value{"bundleID": {Kind: model.StringValue, String: "com.fixture.app"}, "processId": {Kind: model.NumberValue, Number: 42}, "processStartToken": {Kind: model.StringValue, String: "1790000000:1"}}
	for _, mode := range []string{"running", "exited", "missing proof", "reader error", "wrong principal", "wrong predicate"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			a, _ := NewNativeProcessRunning(func(context.Context, auth.Principal, model.Surface) (bool, NativeEvidence, error) {
				calls++
				proof := NativeEvidence{HelperEpoch: "read", TargetRef: "process:42:1790000000:1", ObservedAt: time.Now()}
				if mode == "missing proof" {
					proof = NativeEvidence{}
				}
				if mode == "reader error" {
					return false, proof, errors.New("unavailable")
				}
				return mode == "running", proof, nil
			})
			actor := p
			name := "running"
			if mode == "wrong principal" {
				actor, _ = auth.NewPrincipal("fixture", "", "bob", []string{"desktop:observe"})
			}
			if mode == "wrong predicate" {
				name = "exited"
			}
			r, err := a.Evaluate(ctx, actor, name, inputs)
			switch mode {
			case "running":
				if err != nil || r.Truth != True {
					t.Fatalf("%+v %v", r, err)
				}
			case "exited":
				if err != nil || r.Truth != False {
					t.Fatalf("%+v %v", r, err)
				}
			case "missing proof":
				if err != nil || r.Truth != Unknown {
					t.Fatalf("%+v %v", r, err)
				}
			default:
				if err == nil {
					t.Fatal("invalid evidence accepted")
				}
			}
			if (mode == "wrong principal" || mode == "wrong predicate") && calls != 0 {
				t.Fatal("invalid request reached reader")
			}
		})
	}
}
