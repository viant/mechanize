package chrome

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth/nativepeer"
)

type channelProcessDiagnostic struct {
	reason string
	cause  error
}

func (e *channelProcessDiagnostic) Error() string {
	return "signed Chrome channel verification unavailable"
}
func (e *channelProcessDiagnostic) Unwrap() error { return e.cause }
func channelProcessError(reason string, cause error) error {
	return &channelProcessDiagnostic{reason, cause}
}

// Only fixed source classifications enter status. Neither formatted errors nor
// process identities, executable paths, policy pins or socket tokens are exposed.
func processVerificationReason(err error) string {
	if err == nil {
		return ""
	}
	var stage *channelProcessDiagnostic
	if errors.As(err, &stage) {
		switch stage.reason {
		case "nativeChannelUnavailable", "processEvidenceUnavailable", "kernelPeerUnqualified", "nativeHostIdentityChanged", "chromeIdentityChanged", "desktopAncestryUnqualified", "channelChanged", "scopeChanged":
			return stage.reason
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "processVerificationExpired"
	}
	if errors.Is(err, context.Canceled) {
		return "processVerificationCanceled"
	}
	for _, v := range []struct {
		err  error
		code string
	}{
		{nativepeer.ErrNativePeerAuthentication, "nativePeerAuthenticationUnavailable"},
		{nativepeer.ErrNativePeerAudit, "nativePeerAuditUnavailable"},
		{nativepeer.ErrRunningImageMismatch, "nativeHostImageChanged"},
		{nativepeer.ErrNativeHostSignatureUnavailable, "nativeHostSignatureUnavailable"},
		{nativepeer.ErrChromeSignatureUnavailable, "chromeSignatureUnavailable"},
		{nativepeer.ErrNativeHostProcessUnavailable, "nativeHostProcessUnavailable"},
		{nativepeer.ErrNativeHostUIDUnavailable, "nativeHostUIDChanged"},
		{nativepeer.ErrNativeHostDynamicSignatureUnavailable, "nativeHostDynamicSignatureUnavailable"},
		{nativepeer.ErrChromeAncestryUnavailable, "chromeAncestryUnavailable"},
		{nativepeer.ErrChromeParentUnavailable, "chromeParentUnavailable"},
		{nativepeer.ErrAncestryChanged, "processAncestryChanged"},
	} {
		if errors.Is(err, v.err) {
			return v.code
		}
	}
	return "processVerificationUnavailable"
}
