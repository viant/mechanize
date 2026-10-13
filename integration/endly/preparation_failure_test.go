package endly

import (
	"errors"
	"strings"
	"testing"
)

func TestPreparationDiagnosticsRequirePreIntentResultAndClosedFields(t *testing.T) {
	cause := errors.New("PRIVATE_CANARY provider details")
	provided := NewStepPreparationFailure("qualify", "unavailable", cause)
	if !errors.Is(provided, cause) || strings.Contains(provided.Error(), "PRIVATE_CANARY") {
		t.Fatal("error identity or closed presentation lost")
	}
	copied := CaptureStepPreparationFailure(provided)
	if copied == nil || !copied.Valid() {
		t.Fatal("typed provider phase not captured")
	}
	proven := StepResult{DispatchState: "notDispatched", ExecutionFailure: copied}
	if got := executionFailure(proven, provided); got == nil || got.Preparation.Stage != "qualify" {
		t.Fatal("trusted pre-intent result not captured")
	}
	for _, result := range []StepResult{{}, {DispatchState: "notDispatched"}, {DispatchState: "unknown", ExecutionFailure: copied}, {DispatchState: "dispatched", ExecutionFailure: copied}} {
		if executionFailure(result, provided) != nil {
			t.Fatal("later/unknown input relabeled pre-intent")
		}
	}
	if CaptureStepPreparationFailure(errors.New(provided.Error())) != nil || executionFailure(proven, errors.New(provided.Error())) != nil {
		t.Fatal("plain text reconstructed provenance")
	}
	mismatched := *copied
	detail := *copied.Preparation
	detail.Stage = "readPin"
	mismatched.Preparation = &detail
	if executionFailure(StepResult{DispatchState: "notDispatched", ExecutionFailure: &mismatched}, provided) != nil {
		t.Fatal("different provider phase accepted")
	}
	for _, bad := range []PreparationDiagnostic{{Stage: "PRIVATE_CANARY", Cause: "unavailable"}, {Stage: "qualify", Cause: "PRIVATE_CANARY"}} {
		if CaptureStepPreparationFailure(NewStepPreparationFailure(bad.Stage, bad.Cause, cause)) != nil {
			t.Fatal("arbitrary provider fields accepted")
		}
		invalid := *copied
		invalid.Preparation = &bad
		if invalid.Valid() {
			t.Fatal("invalid serialized phase accepted")
		}
	}
	invalid := *copied
	invalid.DispatchState = "unknown"
	if invalid.Valid() {
		t.Fatal("preparation metadata reported UNKNOWN as no-input")
	}
	invalid = *copied
	invalid.Code = "playwrightDeadline"
	if invalid.Valid() {
		t.Fatal("preparation metadata lent to another failure")
	}
}
