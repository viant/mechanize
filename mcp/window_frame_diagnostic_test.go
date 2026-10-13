package mcp

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestOperationStatusFrameDiagnosticsRemainClosed(t *testing.T) {
	for _, code := range []string{"stalePermit", "windowClickOccluded", "windowHitTestUnavailable", "windowClickUnqualified"} {
		for _, state := range []string{"notDispatched", "unknown"} {
			t.Run(code+"/"+state, func(t *testing.T) {
				testOperationFailureRoundTrip(t, nativeOperationFailureFixture{code, state}, code, state)
			})
		}
	}
	t.Run("local-stale-frame", func(t *testing.T) {
		testOperationFailureRoundTrip(t, &model.MechanizeError{Code: "staleFramePermit", Stage: "native", DispatchState: "notDispatched", EffectState: "none", Message: "PRIVATE_DIAGNOSTIC_CANARY"}, "staleFramePermit", "notDispatched")
	})
}
