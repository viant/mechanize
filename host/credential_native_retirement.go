package host

import (
	"context"
	"errors"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
)

// A normal quit of an exact Chrome process reads no UI or credential values.
// Keep it available while private delivery inhibits observation and ordinary
// input. The typed gateway must independently confirm the original PID/birth
// exited; quitting never closes protection, resolves unknown input, or changes
// the credential ledger. All original policy and control consent still apply.
func privateChromeQuit(step model.Step) bool {
	s := step.Target.Surface
	return step.Action == "app.quit" && s.Kind == "native" && s.BundleID == "com.google.Chrome" && s.ProcessID > 0 && s.ValidateProcessIdentity() == nil && len(step.Arguments) == 0 && step.Validate() == nil
}

func (h *Host) authorizeNativeControlStep(ctx context.Context, p auth.Principal, step model.Step) (*consent.Lease, error) {
	if privateChromeQuit(step) {
		lease, err := h.authorizeConsentOperation(ctx, p, step.Target.Surface, true, consent.Control)
		var detail *model.MechanizeError
		if h.consent != nil && errors.As(err, &detail) && detail.Code == "consentCleanupUnconfirmed" {
			return h.consent.authorizeCleanupQuit(ctx, p)
		}
		return lease, err
	}

	return h.AuthorizeOperation(ctx, p, step.Target.Surface, true, consent.Control)
}
