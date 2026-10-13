package endly

import (
	"context"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"testing"
	"time"
)

func TestExecutionFailureTypedClosedProjection(t *testing.T) {
	typed := &model.MechanizeError{Code: "playwrightTargetChanged", Message: "fixture-private-text", DispatchState: "notDispatched"}
	for _, tc := range []struct {
		name    string
		result  StepResult
		err     error
		want    string
		present bool
	}{
		{"joined", StepResult{DispatchState: "notDispatched"}, errors.Join(errors.New("other private text"), fmt.Errorf("wrapper: %w", typed)), "notDispatched", true},
		{"unknown", StepResult{DispatchState: "unknown"}, typed, "unknown", true},
		{"conflicting", StepResult{DispatchState: "dispatched"}, typed, "unknown", true},
		{"typed fallback", StepResult{}, typed, "notDispatched", true},
		{"flattened", StepResult{DispatchState: "notDispatched"}, errors.New(typed.Error()), "", false},
		{"unlisted", StepResult{DispatchState: "notDispatched"}, &model.MechanizeError{Code: "private-provider-string"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := executionFailure(tc.result, tc.err)
			if (got != nil) != tc.present {
				t.Fatalf("capture presence: %+v", got)
			}
			if got != nil && (got.Code != typed.Code || got.DispatchState != tc.want || !got.Valid()) {
				t.Fatalf("unexpected closed metadata: %+v", got)
			}
		})
	}
}

func TestExecutionFailurePreInputConsentDiagnostic(t *testing.T) {
	for _, code := range []string{"permissionRequired", "permissionExpired", "permissionDenied"} {
		failure := &model.MechanizeError{Code: code, Stage: "consent", DispatchState: "notDispatched", EffectState: "none", Message: "PRIVATE_CANARY"}
		got := executionFailure(StepResult{}, failure)
		if got == nil || got.Code != code || got.DispatchState != "notDispatched" || !got.Valid() {
			t.Fatal("closed pre-input consent failure lost")
		}
		for _, mutate := range []func(*model.MechanizeError){
			func(e *model.MechanizeError) { e.Stage = "native" },
			func(e *model.MechanizeError) { e.DispatchState = "unknown" },
			func(e *model.MechanizeError) { e.EffectState = "unknown" },
		} {
			invalid := *failure
			mutate(&invalid)
			if executionFailure(StepResult{}, &invalid) != nil {
				t.Fatal("unqualified permission claim became consent diagnostic")
			}
		}
	}
}
func TestExecutionFailureBindingCommitRequiresTypedNoInputProof(t *testing.T) {
	proof := &model.MechanizeError{Code: "bindingUnconfirmed", Stage: "browser", DispatchState: "notDispatched", EffectState: "none", Message: "PRIVATE_CANARY"}
	got := executionFailure(StepResult{}, fmt.Errorf("wrapped: %w", proof))
	if got == nil || got.Code != proof.Code || got.DispatchState != "notDispatched" || !got.Valid() {
		t.Fatal("binding commit diagnostic lost")
	}
	for _, mutate := range []func(*model.MechanizeError){
		func(e *model.MechanizeError) { e.Stage = "consent" },
		func(e *model.MechanizeError) { e.DispatchState = "unknown" },
		func(e *model.MechanizeError) { e.EffectState = "unknown" },
	} {
		invalid := *proof
		mutate(&invalid)
		if executionFailure(StepResult{}, &invalid) != nil {
			t.Fatal("unqualified binding failure became no-input proof")
		}
	}
	if executionFailure(StepResult{}, errors.New(proof.Error())) != nil {
		t.Fatal("flattened text became binding diagnostic")
	}
	for _, state := range []string{"dispatched", "unknown"} {
		got := executionFailure(StepResult{DispatchState: state}, proof)
		if got == nil || got.DispatchState != "unknown" {
			t.Fatal("conflicting receipt lost uncertainty")
		}
	}
}

func TestExecutionFailureOwnedRuntimeBoundary(t *testing.T) {
	ctx := actor(t, "failure-owner")
	p, _ := auth.FromContext(ctx)
	p.ClientID = "owner"
	ctx = auth.WithPrincipal(ctx, p)
	r, err := New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (StepResult, error) {
		return StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, fmt.Errorf("wrapped: %w", &model.MechanizeError{Code: "playwrightTargetChanged", Message: "never-export", DispatchState: "notDispatched"})
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "failure")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.SessionID)
	plan, err := script.Compile(`app("com.example.Fixture").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	op, err := r.StartPlan(ctx, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = r.Wait(bounded, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	got, err := r.ExecutionFailure(ctx, session.SessionID, op.ID)
	if err != nil || got == nil || got.DispatchState != "notDispatched" {
		t.Fatalf("capture missing: %+v %v", got, err)
	}
	got.Code = "mutated"
	again, err := r.ExecutionFailure(ctx, session.SessionID, op.ID)
	if err != nil || again.Code != "playwrightTargetChanged" {
		t.Fatal("aliased failure")
	}
	foreign := p
	foreign.ClientID = "other"
	for _, input := range []struct {
		ctx                context.Context
		session, operation string
	}{{auth.WithPrincipal(ctx, foreign), session.SessionID, op.ID}, {ctx, session.SessionID, "wrong"}, {ctx, "wrong", op.ID}} {
		if _, err = r.ExecutionFailure(input.ctx, input.session, input.operation); err == nil {
			t.Fatal("foreign metadata admitted")
		}
	}
}

type nativeFailureFixture struct {
	code, state string
	qualified   bool
}

func (e nativeFailureFixture) Error() string {
	return "PRIVATE_CANARY key/text https://private.test/?credential=fixture"
}
func (e nativeFailureFixture) NativeExecutionFailure() (string, string, bool) {
	return e.code, e.state, e.qualified
}
func TestExecutionFailureNativeClosedProvenanceAndDispatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		result  StepResult
		err     error
		want    string
		present bool
	}{
		{"not dispatched", StepResult{DispatchState: "notDispatched"}, nativeFailureFixture{"foregroundWindowMissing", "notDispatched", true}, "notDispatched", true},
		{"unknown remains", StepResult{DispatchState: "unknown"}, nativeFailureFixture{"foregroundRaiseWindowMissing", "unknown", true}, "unknown", true},
		{"conflict", StepResult{DispatchState: "dispatched"}, nativeFailureFixture{"foregroundWindowInvisible", "notDispatched", true}, "unknown", true},
		{"unqualified", StepResult{}, nativeFailureFixture{"foregroundWindowMissing", "notDispatched", false}, "", false},
		{"not an OS permission claim", StepResult{}, nativeFailureFixture{"permissionDenied", "notDispatched", true}, "", false},
		{"arbitrary code", StepResult{}, nativeFailureFixture{"PRIVATE_CANARY", "notDispatched", true}, "", false},
		{"model error no native provenance", StepResult{}, &model.MechanizeError{Code: "foregroundWindowMissing", Stage: "native", DispatchState: "notDispatched"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := executionFailure(tc.result, tc.err)
			if (got != nil) != tc.present {
				t.Fatal("wrong diagnostic presence", got)
			}
			if got != nil && (got.DispatchState != tc.want || !got.Valid()) {
				t.Fatal("dispatch changed", got)
			}
		})
	}
}

func TestExecutionFailureStaleFramePermitRequiresTypedNoInputProof(t *testing.T) {
	proof := &model.MechanizeError{Code: "staleFramePermit", Message: "private-frame-canary", Stage: "native", DispatchState: "notDispatched", EffectState: "none"}
	for _, tc := range []struct {
		name   string
		result StepResult
		err    error
		want   string
	}{
		{"typed", StepResult{DispatchState: "notDispatched"}, proof, "notDispatched"},
		{"wrapped", StepResult{}, fmt.Errorf("wrapper: %w", proof), "notDispatched"},
		{"unknown retained", StepResult{DispatchState: "unknown"}, proof, "unknown"},
		{"conflicting receipt", StepResult{DispatchState: "dispatched"}, proof, "unknown"},
		{"flattened", StepResult{DispatchState: "notDispatched"}, errors.New(proof.Error()), ""},
		{"native error not local proof", StepResult{DispatchState: "notDispatched"}, nativeFailureFixture{"staleFramePermit", "notDispatched", true}, ""},
		{"ambiguous typed", StepResult{}, &model.MechanizeError{Code: "staleFramePermit", Stage: "native", DispatchState: "unknown", EffectState: "unknown"}, ""},
		{"missing provenance", StepResult{}, &model.MechanizeError{Code: "staleFramePermit", DispatchState: "notDispatched"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := executionFailure(tc.result, tc.err)
			if tc.want == "" {
				if got != nil {
					t.Fatal("unproven expiry projected", got)
				}
				return
			}
			if got == nil || got.Code != "staleFramePermit" || got.DispatchState != tc.want || !got.Valid() {
				t.Fatal("closed expiry projection lost", got)
			}
		})
	}
}
