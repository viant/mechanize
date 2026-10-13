package chrome

import (
	"errors"
	integration "github.com/viant/mechanize/integration/endly"
	"testing"
	"time"
)

func TestPlaywrightProducerCapturesOnlyClosedOperationalMetadata(t *testing.T) {
	execution := &playwrightExecution{started: time.Now().Add(-time.Millisecond), callbackCount: 7, verifyCount: 2, verifyMS: 1, identityChecks: 12, lastCallback: "PRIVATE_CALLBACK", lastMethod: "PRIVATE_CDP"}
	raw := browserError("playwrightDeadline", "PRIVATE_MESSAGE", "notDispatched")
	failure := integration.CaptureExecutionFailure(integration.StepResult{DispatchState: "notDispatched"}, execution.diagnosticFailure(raw))
	if failure == nil || failure.Playwright == nil || !failure.Valid() || failure.Playwright.LastCallback != "none" || failure.Playwright.LastMethod != "none" || failure.Playwright.PeerChecks != 2 {
		t.Fatal("closed producer diagnostics missing")
	}
	if integration.CaptureExecutionFailure(integration.StepResult{}, execution.diagnosticFailure(errors.New(raw.Error()))) != nil {
		t.Fatal("flattened text reconstructed provenance")
	}

}
