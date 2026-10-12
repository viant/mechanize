package objective

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestOutcomeReadDiagnosticsNeverExportAdapterDetails(t *testing.T) {
	actor, _ := auth.NewPrincipal("fixture", "", "diagnostics", []string{"desktop:control"})
	for _, tc := range []struct {
		code, stage, dispatch, want string
	}{
		{"valueMatchUnsupported", "native", "notDispatched", "outcome source unavailable: valueMatchUnsupported"},
		{"valueMatchUnconfirmed", "native", "notDispatched", "outcome source unavailable: valueMatchUnconfirmed"},
		{"valueComparisonDenied", "native", "notDispatched", "outcome source unavailable: valueComparisonDenied"},
		{"valueComparisonUnavailable", "native", "notDispatched", "outcome source unavailable: valueComparisonUnavailable"},
		{"PRIVATE_ERROR_CODE", "native", "notDispatched", "outcome source unavailable"},
		{"valueComparisonDenied", "transport", "notDispatched", "outcome source unavailable"},
		{"valueComparisonDenied", "native", "unknown", "outcome source unavailable"},
		{"valueComparisonDenied", "native", "dispatched", "outcome source unavailable"},
	} {
		t.Run(tc.code+tc.stage+tc.dispatch, func(t *testing.T) {
			failure := errors.Join(errors.New("PRIVATE_WRAPPER"), fmt.Errorf("PRIVATE_CONTEXT: %w", &model.MechanizeError{
				Code: tc.code, Stage: tc.stage, DispatchState: tc.dispatch, Message: "PRIVATE_FIELD_VALUE",
			}))
			evaluator, err := New(map[string]Enrollment{"native": {
				Adapter: adapterFunc(func(context.Context, auth.Principal, string, map[string]model.Value) (Result, error) {
					return Result{}, failure
				}), MaximumAuthority: Observational, AllowedPredicates: map[string]bool{"literalValueMatches": true},
			}})
			if err != nil {
				t.Fatal(err)
			}
			result, err := evaluator.Evaluate(auth.WithPrincipal(context.Background(), actor), actor, model.Predicate{
				Kind: "adapter", Adapter: "native", Name: "literalValueMatches", RequiredAuthority: "observational", TimeoutMs: 1000, FreshnessMs: 1000,
			}, nil)
			if err != nil || result.Truth != Unknown || result.Reason != tc.want || RequireBusinessSuccess(result) == nil {
				t.Fatalf("unexpected diagnostic: %+v, %v", result, err)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), "PRIVATE_") || len(result.Evidence) != 0 {
				t.Fatal("untrusted adapter details escaped")
			}
		})
	}
}
