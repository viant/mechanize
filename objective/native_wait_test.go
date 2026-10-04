package objective

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
	"time"
)

func waitActor(t *testing.T) (context.Context, auth.Principal) {
	t.Helper()
	p, e := auth.NewPrincipal("fixture", "", "wait-owner", []string{"desktop:observe"})
	if e != nil {
		t.Fatal(e)
	}
	p.ClientID = "fixture-client"
	return auth.WithPrincipal(context.Background(), p), p
}
func transientWaitError(code string) error {
	return &model.MechanizeError{Code: code, Stage: "native", DispatchState: "notDispatched"}
}
func TestNativeWaitTransientFalseThenTruePreservesEveryExactReadScope(t *testing.T) {
	ctx, p := waitActor(t)
	ctx, cancel := context.WithTimeout(WithObservationWait(ctx), time.Second)
	defer cancel()
	calls := 0
	input := nativeInputs()
	input["processId"] = model.Value{Kind: model.NumberValue, Number: 4464}
	input["processStartToken"] = model.Value{Kind: model.StringValue, String: "100:1"}
	a, _ := NewNative(func(readCtx context.Context, actor auth.Principal, target model.Selector, attribute string) (model.Value, NativeEvidence, error) {
		calls++
		if actor.Namespace != p.Namespace || actor.ClientID != p.ClientID || target.Surface.ProcessID != 4464 || target.Surface.ProcessStartToken != "100:1" || target.Locator.Value.String != "display" || target.Cardinality != "one" || attribute != "value" {
			t.Fatal("read identity/selector changed")
		}
		if _, ok := readCtx.Deadline(); !ok {
			t.Fatal("predicate deadline lost")
		}
		if calls == 1 {
			return model.Value{}, NativeEvidence{}, transientWaitError("targetNotFound")
		}
		value := "41"
		if calls == 3 {
			value = "42"
		}
		return model.Value{Kind: model.StringValue, String: value}, NativeEvidence{HelperEpoch: "fixture", TargetRef: "display", ObservedAt: time.Now()}, nil
	})
	result, err := a.Evaluate(ctx, p, "valueEquals", input)
	if err != nil || result.Truth != True || calls != 3 {
		t.Fatalf("settling calls=%d truth=%s err=%v", calls, result.Truth, err)
	}
}
func TestNativeWaitOptInAndDeadlineBothRequired(t *testing.T) {
	base, p := waitActor(t)
	for _, mode := range []string{"deadlineOnly", "flagOnly", "neither"} {
		ctx := base
		cancel := func() {}
		if mode == "deadlineOnly" {
			ctx, cancel = context.WithTimeout(ctx, time.Second)
		}
		if mode == "flagOnly" {
			ctx = WithObservationWait(ctx)
		}
		calls := 0
		a, _ := NewNative(func(context.Context, auth.Principal, model.Selector, string) (model.Value, NativeEvidence, error) {
			calls++
			return model.Value{Kind: model.StringValue, String: "41"}, NativeEvidence{HelperEpoch: "fixture", TargetRef: "ref", ObservedAt: time.Now()}, nil
		})
		result, err := a.Evaluate(ctx, p, "valueEquals", nativeInputs())
		cancel()
		if err != nil || result.Truth != False || calls != 1 {
			t.Fatalf("%s snapshot contract changed", mode)
		}
	}
}
func TestNativeWaitPermanentProtectedIdentityAndPermissionFailuresSingleCall(t *testing.T) {
	for _, code := range []string{"permissionDenied", "staleReference", "valueReadDenied", "staticTextReadDenied", "secureInput", "scopeDenied"} {
		ctx, p := waitActor(t)
		ctx, cancel := context.WithTimeout(WithObservationWait(ctx), time.Second)
		calls := 0
		a, _ := NewNative(func(context.Context, auth.Principal, model.Selector, string) (model.Value, NativeEvidence, error) {
			calls++
			return model.Value{}, NativeEvidence{}, transientWaitError(code)
		})
		_, err := a.Evaluate(ctx, p, "valueEquals", nativeInputs())
		cancel()
		if err == nil || calls != 1 {
			t.Fatalf("permanent %s retried", code)
		}
	}
}
func TestNativeWaitFocusedBooleanAndCancellationNeverFalseSuccess(t *testing.T) {
	base, p := waitActor(t)
	ctx, cancel := context.WithTimeout(WithObservationWait(base), time.Second)
	defer cancel()
	calls := 0
	inputs := nativeInputs()
	inputs["attribute"] = model.Value{Kind: model.StringValue, String: "focused"}
	inputs["expected"] = model.Value{Kind: model.BoolValue, Bool: true}
	a, _ := NewNative(func(context.Context, auth.Principal, model.Selector, string) (model.Value, NativeEvidence, error) {
		calls++
		return model.Value{Kind: model.BoolValue, Bool: calls > 1}, NativeEvidence{HelperEpoch: "fixture", TargetRef: "ref", ObservedAt: time.Now()}, nil
	})
	result, err := a.Evaluate(ctx, p, "valueEquals", inputs)
	if err != nil || result.Truth != True || calls != 2 {
		t.Fatal("boolean focused settling failed")
	}
	canceled, stop := context.WithCancel(WithObservationWait(base))
	canceled, deadlineCancel := context.WithTimeout(canceled, time.Second)
	defer deadlineCancel()
	a, _ = NewNative(func(context.Context, auth.Principal, model.Selector, string) (model.Value, NativeEvidence, error) {
		stop()
		return model.Value{Kind: model.BoolValue, Bool: true}, NativeEvidence{HelperEpoch: "fixture", TargetRef: "ref", ObservedAt: time.Now()}, nil
	})
	result, err = a.Evaluate(canceled, p, "valueEquals", inputs)
	if !errors.Is(err, context.Canceled) || result.Truth == True {
		t.Fatal("canceled late true accepted")
	}
}
func TestNativeWaitDeadlineUnknownBoundedAttemptsAndInterval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Millisecond)
	defer cancel()
	calls := 0
	last := time.Time{}
	result, err := waitNativeObservation(ctx, 10*time.Millisecond, 10, func() (Result, error) {
		now := time.Now()
		if !last.IsZero() && now.Sub(last) < 8*time.Millisecond {
			t.Fatal("unbounded polling without interval")
		}
		last = now
		calls++
		return Result{Truth: False, Authority: Observational}, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || result.Truth != Unknown || calls > 3 {
		t.Fatalf("deadline truth=%s calls=%d err=%v", result.Truth, calls, err)
	}
	calls = 0
	result, err = waitNativeObservation(context.Background(), time.Millisecond, 3, func() (Result, error) { calls++; return Result{}, transientWaitError("incompleteObservation") })
	if err == nil || result.Truth != Unknown || calls != 3 {
		t.Fatal("attempt cap ineffective")
	}
}
func TestNativeWaitOuterEvaluatorExpiresUnknownWithoutChangingSnapshotFalse(t *testing.T) {
	base, p := waitActor(t)
	calls := 0
	adapter, _ := NewNative(func(context.Context, auth.Principal, model.Selector, string) (model.Value, NativeEvidence, error) {
		calls++
		return model.Value{Kind: model.StringValue, String: "41"}, NativeEvidence{HelperEpoch: "fixture", TargetRef: "ref", ObservedAt: time.Now()}, nil
	})
	evaluator, _ := New(map[string]Enrollment{"native": adapter.Enrollment()})
	predicate := nativePredicate()
	predicate.TimeoutMs = 60
	snapshot, err := evaluator.Evaluate(base, p, predicate, nil)
	if err != nil || snapshot.Truth != False || calls != 1 {
		t.Fatal("snapshot false contract changed")
	}
	calls = 0
	settled, err := evaluator.Evaluate(WithObservationWait(base), p, predicate, nil)
	if err != nil || settled.Truth != Unknown || settled.Reason != "outcome source deadline exceeded" || calls < 2 {
		t.Fatalf("expiration state %+v calls=%d err=%v", settled, calls, err)
	}
}
