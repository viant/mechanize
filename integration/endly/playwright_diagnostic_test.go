package endly

import (
	"github.com/viant/mechanize/model"
	"testing"
)

type diagnosticFailureFixture struct {
	*model.MechanizeError
	stats PlaywrightDiagnostic
}

func (e diagnosticFailureFixture) Unwrap() error { return e.MechanizeError }
func (e diagnosticFailureFixture) PlaywrightExecutionDiagnostic() PlaywrightDiagnostic {
	return e.stats
}
func TestPlaywrightMetadataRejectsRawLabelsAndUnboundedCounters(t *testing.T) {
	code := "playwrightDeadline"
	valid := PlaywrightDiagnostic{Phase: code, Callbacks: 7, PeerChecks: 2, PeerMs: 1, IdentityChecks: 12, ElapsedMs: 30, LastCallback: "relay.send", LastMethod: "Runtime.getProperties"}
	for _, kind := range []string{"valid", "phase", "callback", "method", "negative", "overflow"} {
		stats := valid
		switch kind {
		case "phase":
			stats.Phase = "PRIVATE_PHASE"
		case "callback":
			stats.LastCallback = "PRIVATE_CALLBACK"
		case "method":
			stats.LastMethod = "PRIVATE_METHOD"
		case "negative":
			stats.PeerMs = -1
		case "overflow":
			stats.Callbacks = 65537
		}
		failure := executionFailure(StepResult{DispatchState: "notDispatched"}, diagnosticFailureFixture{&model.MechanizeError{Code: code, DispatchState: "notDispatched"}, stats})
		if failure == nil || !failure.Valid() || (failure.Playwright != nil) != (kind == "valid") {
			t.Fatal("invalid raw metadata escaped or code lost", kind)
		}
		invalid := ExecutionFailure{Code: code, DispatchState: "notDispatched", Playwright: &stats}
		if invalid.Valid() != (kind == "valid") {
			t.Fatal("controller validity did not enforce closed metadata", kind)
		}
	}
}
