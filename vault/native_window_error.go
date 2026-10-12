package vault

import "errors"

// NativeWindowProbeError is safe for operator-facing diagnostics. Its code is
// selected locally from a closed set: no window/process/source value or raw
// platform error can be incorporated into its message.
type NativeWindowProbeError struct{ status int }

const (
	nativeProbeUnavailable = iota
	nativeProbeAXTrustDenied
	nativeProbeProcessInvalid
	nativeProbeSignatureInvalid
	nativeProbeIPCUnavailable
	nativeProbeWindowShapeUnavailable
	nativeProbeResponseTimeout
	nativeProbeConfigurationInvalid
	nativeProbeConsoleInventoryUnavailable
	nativeProbeContextExpired
	nativeProbeHelperLaunchUnavailable
	nativeProbeHelperProfileUnavailable
	nativeProbeHelperExchangeUnavailable
	nativeProbeHelperCleanupUnconfirmed
)

func (e *NativeWindowProbeError) Code() string {
	if e == nil {
		return "nativeProbeUnavailable"
	}
	switch e.status {
	case nativeProbeAXTrustDenied:
		return "nativeProbeAXTrustDenied"
	case nativeProbeProcessInvalid:
		return "nativeProbeConsoleProcessInvalid"
	case nativeProbeSignatureInvalid:
		return "nativeProbeConsoleSignatureInvalid"
	case nativeProbeIPCUnavailable:
		return "nativeProbeAXIPCUnavailable"
	case nativeProbeWindowShapeUnavailable:
		return "nativeProbeWindowShapeUnavailable"
	case nativeProbeResponseTimeout:
		return "nativeProbeAXResponseTimeout"
	case nativeProbeConfigurationInvalid:
		return "nativeProbeConfigurationInvalid"
	case nativeProbeConsoleInventoryUnavailable:
		return "nativeProbeConsoleInventoryUnavailable"
	case nativeProbeHelperLaunchUnavailable:
		return "nativeProbeHelperLaunchUnavailable"
	case nativeProbeHelperProfileUnavailable:
		return "nativeProbeHelperProfileUnavailable"
	case nativeProbeHelperExchangeUnavailable:
		return "nativeProbeHelperExchangeUnavailable"
	case nativeProbeHelperCleanupUnconfirmed:
		return "nativeProbeHelperCleanupUnconfirmed"
	case nativeProbeContextExpired:
		return "nativeProbeContextExpired"
	default:
		return "nativeProbeUnavailable"
	}
}
func (e *NativeWindowProbeError) Error() string {
	return "native window verification failed: " + e.Code()
}

// Preserve callers' fail-closed ErrUnavailable checks without its misleading
// key/ciphertext message becoming the human-facing diagnosis.
func (e *NativeWindowProbeError) Unwrap() error { return ErrUnavailable }
func nativeProbeFailure(status int) error       { return &NativeWindowProbeError{status: status} }
func sanitizeNativeProbeFailure(err error) error {
	var failure *NativeWindowProbeError
	if errors.As(err, &failure) && failure != nil {
		return nativeProbeFailure(failure.status)
	}
	return nativeProbeFailure(nativeProbeUnavailable)
}
