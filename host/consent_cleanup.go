package host

import (
	"context"
	"encoding/json"
	"time"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
)

// Recovery is observation/lifecycle cleanup only. It posts no keyboard/mouse
// input, quits no user application, reads no fields and replays no old effect.
// Chrome must be fully stopped: an empty new broker registry cannot prove that
// renderer/CDP work admitted by the previous broker has stopped.
func (h *Host) proveConsentCleanup(ctx context.Context, p auth.Principal, scope consent.Scope) error {
	if h.nativeClient == nil || h.nativeControl == nil || scope.Validate() != nil || !p.HasScope("desktop:control") {
		return consent.ErrCleanupUnconfirmed
	}
	doctor, err := h.nativeClient.Call(ctx, native.Request{RequestID: newInfoID(), Method: "doctor", DeadlineRemainingMS: 1000})
	if err != nil || doctor.Error != nil || doctor.HelperEpoch == "" {
		return consent.ErrCleanupUnconfirmed
	}
	reply, err := h.nativeClient.Call(ctx, native.Request{RequestID: newInfoID(), Method: "apps.list", HelperEpoch: doctor.HelperEpoch, Params: json.RawMessage(`{"expectedApp":"com.google.Chrome"}`), DeadlineRemainingMS: 1000})
	var inventory struct {
		Complete bool `json:"complete"`
		Apps     []struct {
			BundleID string `json:"bundleID"`
		} `json:"apps"`
	}
	if err != nil || reply.Error != nil || reply.HelperEpoch != doctor.HelperEpoch || json.Unmarshal(reply.Result, &inventory) != nil || !inventory.Complete {
		return consent.ErrCleanupUnconfirmed
	}
	for _, app := range inventory.Apps {
		if app.BundleID == "com.google.Chrome" {
			return consent.ErrCleanupUnconfirmed
		}
	}
	return h.proveNativePhysicalCleanup(ctx, p)
}

// Native physical cleanup is independent of browser executor cleanup. This
// proof is used only for an exact non-browser application operation; the
// original suspended consent and all browser/UNKNOWN history remain unchanged.
func (h *Host) proveNativeConsentCleanup(ctx context.Context, p auth.Principal, scope consent.Scope) error {
	if scope.Kind != "application" || scope.BundleID == "com.google.Chrome" || scope.Validate() != nil {
		return consent.ErrCleanupUnconfirmed
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return h.proveNativePhysicalCleanup(bounded, p)
}

func (h *Host) proveNativePhysicalCleanup(ctx context.Context, p auth.Principal) error {
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || h.nativeClient == nil || h.nativeControl == nil || !p.HasScope("desktop:control") {
		return consent.ErrCleanupUnconfirmed
	}
	if err = h.proveReleasedNativeInput(ctx, p); err != nil {
		return consent.ErrCleanupUnconfirmed
	}
	// Acquire independently checks the persisted old helper identity/fence and
	// reconciles unknown held input through the signed observation helper. A
	// nil in-memory registry is deliberately insufficient.
	if _, err = h.admitNativeControl(ctx, p); err != nil {
		return consent.ErrCleanupUnconfirmed
	}
	report, err := h.nativeControl.Revoke(ctx, p)
	if err != nil || !report.InputInhibited || !report.HelperStopped || !report.FenceReleased || report.UnknownInputs {
		return consent.ErrCleanupUnconfirmed
	}
	return nil
}

// A completed authenticated reconnect can replace browser-process death, but
// only while its exact old-to-new fence proof remains sealed and unused. The
// guard spans the generated consent CAS; no READY flag/empty registry suffices.
func (h *Host) withConsentCleanupProof(ctx context.Context, p auth.Principal, scope consent.Scope, commit func(context.Context) error) error {
	if commit == nil || scope.Validate() != nil {
		return consent.ErrCleanupUnconfirmed
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if h.chrome != nil {
		if err := h.proveNativePhysicalCleanup(bounded, p); err != nil {
			return consent.ErrCleanupUnconfirmed
		}
		called := false
		err := h.chrome.WithConsentReconnectProof(bounded, p, func() error { called = true; return commit(bounded) })
		if err == nil || called {
			return err
		}
	}
	if err := h.proveConsentCleanup(bounded, p, scope); err != nil {
		return consent.ErrCleanupUnconfirmed
	}
	return commit(bounded)
}
