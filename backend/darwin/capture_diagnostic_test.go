package darwin

import "testing"

func TestFrameCaptureDiagnosticPreservesExistingRecipientRejections(t *testing.T) {
	for _, code := range []string{"windowKeyboardUnqualified", "sessionUnqualified", "foregroundRefreshUnavailable"} {
		failure := &CaptureError{Phase: "nativeCapture", CauseCode: code}
		if phase, cause := failure.Diagnostic(); phase != "nativeCapture" || cause != code {
			t.Fatalf("existing frame rejection lost: phase=%q cause=%q", phase, cause)
		}
	}
	for _, failure := range []*CaptureError{{Phase: "nativeCapture", CauseCode: "PRIVATE_CANARY"}, {Phase: "PRIVATE_CANARY", CauseCode: "windowKeyboardUnqualified"}} {
		if phase, cause := failure.Diagnostic(); phase != "" || cause != "" {
			t.Fatal("unbounded capture diagnostic admitted")
		}
	}
}
