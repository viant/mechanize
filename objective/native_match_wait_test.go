package objective

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestLiteralComparisonSettlesOnlyUnavailablePostconditionWithFreshProof(t *testing.T) {
	for _, mode := range []string{"settle", "snapshot", "denied", "uncertain", "stale-process", "missing-proof", "deadline", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := auth.NewPrincipal("fixture", "", "comparison-wait", []string{"desktop:control"})
			ctx := auth.WithPrincipal(context.Background(), p)
			if mode != "snapshot" {
				ctx = WithObservationWait(ctx)
			}
			ctx, cancel := context.WithTimeout(ctx, 160*time.Millisecond)
			defer cancel()
			calls := 0
			a, _ := NewNativeWithMatcher(func(context.Context, auth.Principal, model.Selector, string) (model.Value, NativeEvidence, error) {
				t.Fatal("comparison cannot export the field value")
				return model.Value{}, NativeEvidence{}, nil
			}, func(_ context.Context, actor auth.Principal, target model.Selector, expected string) (bool, NativeEvidence, error) {
				calls++
				if actor.Namespace != p.Namespace || target.Surface.ProcessID != 123 || target.Surface.ProcessStartToken != "100:1" || target.Scope.Window["title"].String != "Fixture" || target.Locator.Value.String != "display" || expected != "public fixture value" {
					t.Fatal("fresh comparison changed its original scope or literal")
				}
				if calls == 1 || mode == "deadline" {
					code, dispatch := "valueComparisonUnavailable", "notDispatched"
					if mode == "denied" {
						code = "valueComparisonDenied"
					}
					if mode == "uncertain" {
						dispatch = "unknown"
					}
					if mode == "stale-process" {
						code = "staleReference"
					}
					if mode == "cancelled" {
						cancel()
					}
					return false, NativeEvidence{}, &model.MechanizeError{Code: code, Stage: "native", DispatchState: dispatch}
				}
				proof := NativeEvidence{HelperEpoch: "helper", TargetRef: "fresh-field", ObservedAt: time.Now()}
				if mode == "missing-proof" {
					proof.TargetRef = ""
				}
				return true, proof, nil
			})
			inputs := nativeInputs()
			for key, value := range map[string]string{"expected": "public fixture value", "windowTitle": "Fixture", "processStartToken": "100:1"} {
				inputs[key] = model.Value{Kind: model.StringValue, String: value}
			}
			inputs["processId"] = model.Value{Kind: model.NumberValue, Number: 123}
			result, err := a.Evaluate(ctx, p, "literalValueMatches", inputs)
			if mode == "settle" {
				if err != nil || result.Truth != True || calls != 2 {
					t.Fatalf("not settled: %+v %v calls=%d", result, err, calls)
				}
			} else {
				if result.Truth == True {
					t.Fatal("invalid comparison accepted")
				}
				if mode == "missing-proof" && calls != 2 || mode == "deadline" && (calls < 2 || calls > 4) || mode != "missing-proof" && mode != "deadline" && calls != 1 {
					t.Fatalf("unexpected %s read count %d", mode, calls)
				}
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), "public fixture value") {
				t.Fatal("compared literal escaped")
			}
		})
	}
}
