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

func TestLiteralNativeComparisonPreservesScopeWithoutReturningValue(t *testing.T) {
	for _, mode := range []string{"match", "different", "noControl", "noProcess", "metadataAttribute", "missingProof", "callbackFailure", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := auth.NewPrincipal("fixture", "", "literal-match", []string{"desktop:control"})
			if mode == "noControl" {
				p.Scopes = []string{"desktop:observe"}
			}
			ctx, cancel := context.WithCancel(auth.WithPrincipal(context.Background(), p))
			defer cancel()
			calls := 0
			a, err := NewNativeWithMatcher(func(context.Context, auth.Principal, model.Selector, string) (model.Value, NativeEvidence, error) {
				t.Fatal("ordinary value read must not run")
				return model.Value{}, NativeEvidence{}, nil
			}, func(ctx context.Context, _ auth.Principal, target model.Selector, expected string) (bool, NativeEvidence, error) {
				calls++
				if target.Scope.NativeRoot != "focusedElement" || target.Surface.ProcessID != 123 || target.Surface.ProcessStartToken != "1791032156:839822" || expected != "public comparison text" {
					t.Fatal("literal comparison scope changed")
				}
				proof := NativeEvidence{HelperEpoch: "helper", TargetRef: "field", ObservedAt: time.Now()}
				if mode == "missingProof" {
					proof.TargetRef = ""
				}
				if mode == "callbackFailure" {
					return false, NativeEvidence{}, context.DeadlineExceeded
				}
				if mode == "cancelled" {
					cancel()
				}
				return mode != "different", proof, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			inputs := nativeInputs()
			inputs["expected"] = model.Value{Kind: model.StringValue, String: "public comparison text"}
			inputs["nativeRoot"] = model.Value{Kind: model.StringValue, String: "focusedElement"}
			inputs["processId"] = model.Value{Kind: model.NumberValue, Number: 123}
			inputs["processStartToken"] = model.Value{Kind: model.StringValue, String: "1791032156:839822"}
			if mode == "noProcess" {
				delete(inputs, "processId")
				delete(inputs, "processStartToken")
			}
			if mode == "metadataAttribute" {
				inputs["attribute"] = model.Value{Kind: model.StringValue, String: "name"}
			}
			result, err := a.Evaluate(ctx, p, "literalValueMatches", inputs)
			switch mode {
			case "match":
				if err != nil || result.Truth != True {
					t.Fatalf("match not proved: %+v %v", result, err)
				}
			case "different":
				if err != nil || result.Truth != False {
					t.Fatalf("mismatch not retained: %+v %v", result, err)
				}
			case "missingProof":
				if err != nil || result.Truth != Unknown {
					t.Fatal("incomplete proof accepted")
				}
			default:
				if err == nil {
					t.Fatal("unqualified comparison accepted")
				}
			}
			if (mode == "noControl" || mode == "noProcess" || mode == "metadataAttribute") && calls != 0 {
				t.Fatal("denied comparison reached helper")
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), "public comparison text") {
				t.Fatal("compared content leaked in evidence")
			}
		})
	}
}
