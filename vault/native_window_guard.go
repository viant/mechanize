package vault

import (
	"context"
	"errors"
	"github.com/viant/mechanize/backend/darwin"
	"os"
	"strings"
)

// SecureEntryWindowTitlePrefix is a fixed native console contract. The title
// may contain only this prefix plus the opaque entry ID, never account data.
const SecureEntryWindowTitlePrefix = "Mechanize Secure Entry "

type NativeWindowOptions struct {
	// Helper is explicit trusted enrollment, never an error-triggered fallback.
	Helper             *darwin.PrivateAdministration
	ExpectedUID        uint32
	ConsoleRequirement string
}
type nativeWindowState struct {
	consoles  int
	protected bool
	entries   int
	matched   int
}
type nativeWindowProbe func(context.Context, string) (nativeWindowState, error)
type nativeEntryWindows struct{ probe nativeWindowProbe }

// NewNativeWindowProtection creates the actual platform window verifier and
// shares its startup/restart guard with entry and host exposure admission.
// It never creates a credential window, provisions keys or grants TCC access.
func NewNativeWindowProtection(options NativeWindowOptions) (*ExposureGate, *NativeEntryController, error) {
	if options.ExpectedUID != uint32(os.Getuid()) || strings.TrimSpace(options.ConsoleRequirement) == "" || strings.ContainsRune(options.ConsoleRequirement, 0) {
		return nil, nil, nativeProbeFailure(nativeProbeConfigurationInvalid)
	}
	var probe nativeWindowProbe
	var err error
	if options.Helper != nil {
		probe = helperWindowProbe(options.ConsoleRequirement, options.Helper.ConsoleWindows)
	} else {
		probe, err = newNativeWindowProbe(options)
	}
	if err != nil {
		return nil, nil, sanitizeNativeProbeFailure(err)
	}
	return newNativeWindowProtection(probe)
}
func newNativeWindowProtection(probe nativeWindowProbe) (*ExposureGate, *NativeEntryController, error) {
	if probe == nil {
		return nil, nil, ErrUnavailable
	}
	windows := &nativeEntryWindows{probe: probe}
	gate, err := NewGuardedExposureGate(func(ctx context.Context) error {
		state, err := probe(ctx, "")
		if err != nil {
			return sanitizeNativeProbeFailure(err)
		}
		if state.protected {
			return ErrEntryProtected
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	controller, err := NewNativeEntryController(gate, windows)
	return gate, controller, err
}
func (w *nativeEntryWindows) Prepare(ctx context.Context, id string, target Target) error {
	if !nativeRevision(id) || target.Validate() != nil {
		return ErrUnavailable
	}
	state, err := w.probe(ctx, "")
	if err != nil || state.consoles != 1 || state.protected {
		return ErrUnavailable
	}
	return nil
}
func (w *nativeEntryWindows) VerifyOpen(ctx context.Context, id string) error {
	if !nativeRevision(id) {
		return ErrUnavailable
	}
	state, err := w.probe(ctx, id)
	if err != nil || state.consoles != 1 || !state.protected || state.entries != 1 || state.matched != 1 {
		return ErrUnavailable
	}
	return nil
}
func (w *nativeEntryWindows) VerifyClosed(ctx context.Context, id string) error {
	if id != "" && !nativeRevision(id) {
		return ErrEntryCleanup
	}
	state, err := w.probe(ctx, "")
	if err != nil || state.protected {
		return ErrEntryCleanup
	}
	return nil
}

func helperWindowProbe(requirement string, read func(context.Context, string, string) (darwin.PrivateConsoleWindows, error)) nativeWindowProbe {
	return func(ctx context.Context, id string) (nativeWindowState, error) {
		state, e := read(ctx, requirement, id)
		if e != nil {
			return nativeWindowState{}, helperWindowFailure(e)
		}
		return nativeWindowState{consoles: state.Consoles, protected: state.Entries > 0, entries: state.Entries, matched: state.Matched}, nil
	}
}

func helperWindowFailure(err error) error {
	var failure *darwin.PrivateProofError
	if errors.As(err, &failure) {
		switch failure.Code() {
		case "privateAXTrustDenied":
			return nativeProbeFailure(nativeProbeAXTrustDenied)
		case "privateConsoleSignatureInvalid":
			return nativeProbeFailure(nativeProbeSignatureInvalid)
		case "privateConsoleProcessInvalid":
			return nativeProbeFailure(nativeProbeProcessInvalid)
		case "privateConsoleInventoryUnavailable":
			return nativeProbeFailure(nativeProbeConsoleInventoryUnavailable)
		case "privateAXIPCUnavailable":
			return nativeProbeFailure(nativeProbeIPCUnavailable)
		case "privateWindowShapeUnavailable":
			return nativeProbeFailure(nativeProbeWindowShapeUnavailable)
		case "privateHelperTimeout":
			return nativeProbeFailure(nativeProbeResponseTimeout)
		case "privateHelperLaunchUnavailable":
			return nativeProbeFailure(nativeProbeHelperLaunchUnavailable)
		case "privateHelperDoctorUnavailable", "privateHelperProfileUnavailable":
			return nativeProbeFailure(nativeProbeHelperProfileUnavailable)
		case "privateHelperCleanupUnconfirmed":
			return nativeProbeFailure(nativeProbeHelperCleanupUnconfirmed)
		default:
			return nativeProbeFailure(nativeProbeHelperExchangeUnavailable)
		}
	}
	return nativeProbeFailure(nativeProbeUnavailable)
}
