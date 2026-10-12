package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNativeProbeDiagnosticsSurviveBothExposureGuards(t *testing.T) {
	codes := []string{"nativeProbeUnavailable", "nativeProbeAXTrustDenied", "nativeProbeConsoleProcessInvalid", "nativeProbeConsoleSignatureInvalid", "nativeProbeAXIPCUnavailable", "nativeProbeWindowShapeUnavailable", "nativeProbeAXResponseTimeout", "nativeProbeConfigurationInvalid", "nativeProbeConsoleInventoryUnavailable", "nativeProbeContextExpired", "nativeProbeHelperLaunchUnavailable", "nativeProbeHelperProfileUnavailable", "nativeProbeHelperExchangeUnavailable", "nativeProbeHelperCleanupUnconfirmed"}
	for status, code := range codes {
		t.Run(code, func(t *testing.T) {
			probe := func(context.Context, string) (nativeWindowState, error) {
				return nativeWindowState{}, fmt.Errorf("private-title-pid-source-canary: %w", nativeProbeFailure(status))
			}
			gate, _, err := newNativeWindowProtection(probe)
			if err != nil {
				t.Fatal(err)
			}
			release, err := gate.AcquireExposure()
			var diagnostic *NativeWindowProbeError
			if release != nil || !errors.Is(err, ErrUnavailable) || !errors.As(err, &diagnostic) || diagnostic.Code() != code {
				t.Fatal("diagnostic lost or failed probe admitted exposure")
			}
			if err.Error() != "native window verification failed: "+code || strings.Contains(err.Error(), "canary") {
				t.Fatal("diagnostic includes remote values")
			}
			// Refusal must not increment active readers or change entry state.
			if gate.readers != 0 || gate.entry != nil {
				t.Fatal("failed probe changed gate state")
			}
		})
	}
}
func TestNativeProbeUnknownAndContextFailuresAreSafe(t *testing.T) {
	for _, incoming := range []error{errors.New("private-source-canary"), nativeProbeFailure(-123), nativeProbeFailure(1000)} {
		gate, _ := NewGuardedExposureGate(func(context.Context) error { return incoming })
		release, err := gate.AcquireExposure()
		var diagnostic *NativeWindowProbeError
		if release != nil || !errors.As(err, &diagnostic) || diagnostic.Code() != "nativeProbeUnavailable" || strings.Contains(err.Error(), "canary") {
			t.Fatal("unknown probe failure was exposed")
		}
	}
	calls := 0
	gate, _ := NewGuardedExposureGate(func(context.Context) error { calls++; return nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	release, err := gate.AcquireExposureContext(ctx)
	var diagnostic *NativeWindowProbeError
	if release != nil || calls != 0 || !errors.As(err, &diagnostic) || diagnostic.Code() != "nativeProbeContextExpired" {
		t.Fatal("expired context was not classified before probing")
	}
}
