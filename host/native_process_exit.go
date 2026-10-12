package host

import (
	"context"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

func (h *Host) readNativeProcessExit(ctx context.Context, p auth.Principal, surface model.Surface) (bool, objective.NativeEvidence, error) {
	user, err := h.authorize(ctx, p)
	if err != nil {
		return false, objective.NativeEvidence{}, err
	}
	permitted := user.DesktopAccess
	for _, bundle := range user.NativeBundles {
		permitted = permitted || bundle == surface.BundleID
	}
	if !permitted || surface.Kind != "native" || surface.ProcessID <= 0 || surface.ValidateProcessIdentity() != nil {
		return false, objective.NativeEvidence{}, auth.ErrUnauthorized
	}
	gateway := h.nativeFor(p.Namespace)
	if gateway == nil {
		return false, objective.NativeEvidence{}, ErrNativeControlUnqualified
	}
	// Exact process-exit evidence is a closed boolean, never UI, clipboard or
	// credential content. Keep this metadata read available while private delivery
	// protects observation, so an uncertain normal quit can be reconciled.
	lease, err := h.authorizeConsentOperation(ctx, p, surface, false, consent.Observe)
	if err != nil {
		return false, objective.NativeEvidence{}, err
	}
	defer lease.Release()
	proof, err := gateway.ProcessExit(lease.Context, p, surface)
	if err != nil {
		return false, objective.NativeEvidence{}, err
	}
	return proof.ExitConfirmed, objective.NativeEvidence{HelperEpoch: proof.HelperEpoch, TargetRef: proof.TargetRef, ObservedAt: proof.ObservedAt}, nil
}
