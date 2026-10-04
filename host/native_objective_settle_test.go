package host

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

func settlingNativePredicate() model.Predicate {
	inputs := map[string]model.Value{}
	for key, value := range map[string]string{"bundleID": "com.example.Fixture", "strategy": "id", "selector": "next", "attribute": "enabled"} {
		inputs[key] = model.Value{Kind: model.StringValue, String: value}
	}
	inputs["expected"] = model.Value{Kind: model.BoolValue, Bool: true}
	return model.Predicate{Kind: "adapter", Adapter: "native", Name: "valueEquals", Inputs: inputs, RequiredAuthority: "observational", TimeoutMs: 200, FreshnessMs: 200}
}

func TestNativePredicateHelperErrorsSettleOnlyWithPostconditionOptIn(t *testing.T) {
	for _, code := range []string{"targetNotFound", "incompleteObservation", "attributeUnavailable"} {
		t.Run(code, func(t *testing.T) {
			p, _ := auth.NewPrincipal("fixture", "", "native-settle", []string{"desktop:observe"})
			base := auth.WithPrincipal(context.Background(), p)
			helperErr := &native.NativeError{Code: code, Message: "temporarily unavailable", Stage: "native", RetryableRead: true, DispatchState: "notDispatched"}
			calls := 0
			adapter, _ := objective.NewNative(func(ctx context.Context, actor auth.Principal, target model.Selector, attribute string) (model.Value, objective.NativeEvidence, error) {
				calls++
				if target.Surface.BundleID != "com.example.Fixture" || target.Locator.Value.String != "next" || attribute != "enabled" || actor.Namespace != p.Namespace {
					t.Fatal("read scope changed")
				}
				if calls == 1 {
					return model.Value{}, objective.NativeEvidence{}, nativePredicateError(fmt.Errorf("helper read: %w", helperErr))
				}
				return model.Value{Kind: model.BoolValue, Bool: true}, objective.NativeEvidence{HelperEpoch: "epoch", TargetRef: "next", ObservedAt: time.Now()}, nil
			})
			evaluator, _ := objective.New(map[string]objective.Enrollment{"native": adapter.Enrollment()})
			snapshot, err := evaluator.Evaluate(base, p, settlingNativePredicate(), nil)
			if err != nil || calls != 1 || snapshot.Truth != objective.Unknown || snapshot.Reason != "outcome source unavailable" {
				t.Fatalf("snapshot: %+v calls=%d err=%v", snapshot, calls, err)
			}
			calls = 0
			result, err := evaluator.Evaluate(objective.WithObservationWait(base), p, settlingNativePredicate(), nil)
			if err != nil || result.Truth != objective.True || calls != 2 {
				t.Fatalf("settled: %+v calls=%d err=%v", result, calls, err)
			}
		})
	}
}

func TestNativePredicateErrorBridgeKeepsPermanentAndTransportFailuresOneShot(t *testing.T) {
	for _, failure := range []error{
		auth.ErrUnauthorized,
		&native.NativeError{Code: "ownerMismatch", Stage: "native"},
		&native.NativeError{Code: "staleEpoch", Stage: "native"},
		&native.NativeError{Code: "ambiguousTarget", Stage: "native"},
		&native.NativeError{Code: "permissionDenied", Stage: "native"},
		&native.NativeError{Code: "targetNotFound", Stage: "policy"},
		&native.NativeError{Code: "targetNotFound", Stage: "native", DispatchState: "unknown"},
		&native.NativeError{Code: "targetNotFound", Stage: "native", DispatchState: "dispatched"},
		&native.TransportError{Cause: &native.NativeError{Code: "targetNotFound", Stage: "native"}, DispatchState: "unknown"},
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			mapped := nativePredicateError(failure)
			if !errors.Is(mapped, failure) {
				t.Fatal("original error lost")
			}
			p, _ := auth.NewPrincipal("fixture", "", "native-permanent", []string{"desktop:observe"})
			ctx := auth.WithPrincipal(context.Background(), p)
			calls := 0
			adapter, _ := objective.NewNative(func(context.Context, auth.Principal, model.Selector, string) (model.Value, objective.NativeEvidence, error) {
				calls++
				return model.Value{}, objective.NativeEvidence{}, mapped
			})
			evaluator, _ := objective.New(map[string]objective.Enrollment{"native": adapter.Enrollment()})
			result, err := evaluator.Evaluate(objective.WithObservationWait(ctx), p, settlingNativePredicate(), nil)
			if err != nil || result.Truth != objective.Unknown || calls != 1 {
				t.Fatalf("permanent failure retried: %+v calls=%d err=%v", result, calls, err)
			}
		})
	}
}

func TestNativePredicateHelperSettlingRetainsDeadlineCancellationAndFreshness(t *testing.T) {
	for _, mode := range []string{"deadline", "canceled", "stale"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := auth.NewPrincipal("fixture", "", "native-bounds", []string{"desktop:observe"})
			ctx, cancel := context.WithCancel(auth.WithPrincipal(context.Background(), p))
			defer cancel()
			calls := 0
			adapter, _ := objective.NewNative(func(context.Context, auth.Principal, model.Selector, string) (model.Value, objective.NativeEvidence, error) {
				calls++
				if mode == "canceled" {
					cancel()
				}
				if calls == 1 || mode == "deadline" || mode == "canceled" {
					return model.Value{}, objective.NativeEvidence{}, nativePredicateError(&native.NativeError{Code: "targetNotFound", Stage: "native", DispatchState: "notDispatched"})
				}
				return model.Value{Kind: model.BoolValue, Bool: true}, objective.NativeEvidence{HelperEpoch: "epoch", TargetRef: "next", ObservedAt: time.Now().Add(-time.Hour)}, nil
			})
			evaluator, _ := objective.New(map[string]objective.Enrollment{"native": adapter.Enrollment()})
			result, _ := evaluator.Evaluate(objective.WithObservationWait(ctx), p, settlingNativePredicate(), nil)
			if result.Truth != objective.Unknown {
				t.Fatalf("%s accepted invalid evidence: %+v", mode, result)
			}
			if mode == "canceled" && calls != 1 || mode == "deadline" && (calls < 2 || calls > 5) || mode == "stale" && calls != 2 {
				t.Fatalf("%s settling calls=%d", mode, calls)
			}
		})
	}
}

func TestNativePredicateErrorBridgePreservesTypedDetails(t *testing.T) {
	if nativePredicateError(nil) != nil {
		t.Fatal("nil error changed")
	}
	helper := &native.NativeError{Code: "targetNotFound", Stage: "native", Message: "fixture unavailable", RetryableRead: true, DispatchState: "notDispatched"}
	mapped := nativePredicateError(helper)
	var original *native.NativeError
	var detail *model.MechanizeError
	if !errors.As(mapped, &original) || original != helper || !errors.As(mapped, &detail) || detail.Code != helper.Code || detail.Stage != helper.Stage || detail.Message != helper.Message || detail.RetryableRead != helper.RetryableRead || detail.DispatchState != helper.DispatchState {
		t.Fatal("typed native error details changed")
	}
}
