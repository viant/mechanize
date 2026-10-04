package host

import (
	"context"
	"errors"
	"reflect"

	"github.com/viant/mechanize/auth"
	repairs "github.com/viant/mechanize/engine/recovery"
)

// recoveryRuntimeReady establishes the live owned session required for later
// explicit resume. It does not assert evidence qualification or admit input.
func (h *Host) recoveryRuntimeReady(ctx context.Context, p auth.Principal) error {
	if h.Runtime == nil || h.nativeControl == nil {
		return errors.New("native recovery runtime unavailable")
	}
	if _, err := h.authorize(ctx, p); err != nil {
		return err
	}
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || binding.SessionID == "" || binding.Purpose == "" {
		return errors.New("owned recovery session and purpose required")
	}
	if err := h.Runtime.CheckSession(ctx, p, binding.SessionID); err != nil {
		return err
	}
	return ctx.Err()
}

func validateNativeRecoveryBoundary(snapshot repairs.Snapshot, expected repairs.RunReference) error {
	if !reflect.DeepEqual(snapshot.Reference, expected) || snapshot.Unknown || (snapshot.Reference.Status != "paused" && snapshot.Reference.Status != "new") {
		return errors.New("exact stopped recovery boundary changed or remains uncertain")
	}
	if len(snapshot.Plan.Steps) == 0 {
		return errors.New("original recovery plan unavailable")
	}
	for _, step := range snapshot.Plan.Steps {
		if step.Target.Surface.Kind != "native" {
			return errors.New("recovery executor guard currently qualifies native plans only")
		}
	}
	return nil
}

// recoveryGuard shares the proven Endly admission/native executor fence used
// for reconciliation. No input helper is acquired. Read back the exact durable
// boundary under the held fence; release failures must reach the repair result.
func (h *Host) recoveryGuard(ctx context.Context, p auth.Principal, ref repairs.RunReference) (func() error, error) {
	if h.recovery == nil {
		return nil, errors.New("recovery state unavailable")
	}
	if err := h.recoveryRuntimeReady(ctx, p); err != nil {
		return nil, err
	}
	release, err := h.effectReconciliationGuard(ctx, p, ref.RunID)
	if err != nil {
		return nil, err
	}
	snapshot, err := h.recovery.Snapshot(ctx, p, ref.RunID)
	if err == nil {
		err = validateNativeRecoveryBoundary(snapshot, ref)
	}
	if err != nil {
		return nil, errors.Join(err, release())
	}
	return release, nil
}
