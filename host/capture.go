package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
)

func captureUnsupported(message string) error {
	return &model.MechanizeError{Code: "unsupported", Message: message, Stage: "capture", DispatchState: "notDispatched"}
}
func (h *Host) capturePrincipal(ctx context.Context, requested auth.Principal, surface model.Surface) (auth.Principal, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || requested.Validate() != nil || actual.Namespace != requested.Namespace {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	user, err := h.authorize(ctx, actual)
	if err != nil {
		return auth.Principal{}, err
	}
	if surface.Kind != "native" {
		return auth.Principal{}, captureUnsupported("Only an exact native application window can be captured")
	}
	if surface.BundleID == "" || surface.Origin != "" || surface.TabID != "" || surface.Title != "" {
		return auth.Principal{}, captureUnsupported("Capture requires an exact application bundle and physical window identity")
	}
	if err := surface.ValidateProcessIdentity(); err != nil {
		return auth.Principal{}, err
	}
	if user.DesktopAccess {
		return actual, nil
	}
	for _, bundle := range user.NativeBundles {
		if bundle == surface.BundleID {
			return actual, nil
		}
	}
	return auth.Principal{}, auth.ErrUnauthorized
}

// CaptureWindow consumes one exact observe grant and retains it through helper
// cleanup, encrypted storage, and durable metadata publication. Physical window
// ownership is rechecked in the helper, independently of caller-provided IDs.
func (h *Host) CaptureWindow(ctx context.Context, requested auth.Principal, surface model.Surface, pid int32, windowID uint32) (data.ArtifactReference, native.CapturedImage, error) {
	p, err := h.capturePrincipal(ctx, requested, surface)
	if err != nil {
		return data.ArtifactReference{}, native.CapturedImage{}, err
	}
	if h.captureHelper == "" || h.captureWindow == nil || h.captureMaxBytes <= 0 || h.captureMaxBytes > native.MaximumCaptureBytes || h.artifacts == nil {
		return data.ArtifactReference{}, native.CapturedImage{}, captureUnsupported("Native capture helper and encrypted artifact publication must be configured")
	}
	if pid <= 0 || windowID == 0 {
		return data.ArtifactReference{}, native.CapturedImage{}, errors.New("exact positive PID and physical window ID required")
	}
	if surface.ProcessID != 0 && surface.ProcessID != int(pid) {
		return data.ArtifactReference{}, native.CapturedImage{}, errors.New("capture PID differs from narrowed native process")
	}
	lease, err := h.AuthorizeOperation(ctx, p, surface, false, consent.Observe)
	if err != nil {
		return data.ArtifactReference{}, native.CapturedImage{}, err
	}
	return h.captureWindowWithLease(p, surface, pid, windowID, lease)
}

func (h *Host) captureWindowWithLease(p auth.Principal, surface model.Surface, pid int32, windowID uint32, lease *consent.Lease) (data.ArtifactReference, native.CapturedImage, error) {
	if lease == nil || lease.Context == nil || lease.Release == nil {
		return data.ArtifactReference{}, native.CapturedImage{}, errors.New("complete capture consent lease required")
	}
	ctx, cancel := context.WithCancel(lease.Context)
	defer cancel()
	image, err := h.captureWindow(ctx, native.WindowCaptureOptions{HelperPath: h.captureHelper, BundleID: surface.BundleID, PID: pid, ProcessStartToken: surface.ProcessStartToken, WindowID: windowID, MaxBytes: h.captureMaxBytes})
	if err != nil {
		var failure *native.CaptureError
		if errors.As(err, &failure) && failure.CleanupConfirmed {
			lease.Release()
		}
		return data.ArtifactReference{}, native.CapturedImage{}, err
	}
	// Successful low-level capture confirms disposable helper teardown. Publication
	// remains inside the retained consent interval; errors never delete durable bytes.
	defer lease.Release()
	m := image.Metadata
	if surface.ProcessStartToken != "" && m.ProcessStartToken != surface.ProcessStartToken {
		return data.ArtifactReference{}, native.CapturedImage{}, errors.New("capture process birth identity changed")
	}
	if m.BundleID != surface.BundleID || m.PID != pid || m.WindowID != windowID || m.Identity != fmt.Sprintf("window:%d", windowID) || len(image.PNG) == 0 || len(image.PNG) > h.captureMaxBytes || m.Bytes != len(image.PNG) {
		return data.ArtifactReference{}, native.CapturedImage{}, errors.New("trusted capture returned mismatched window evidence")
	}
	ref, err := h.artifacts.publishBound(ctx, p, "image/png", bytes.NewReader(image.PNG))
	return ref, image, err
}

// CaptureWindows discovers bounded physical identities under exact application
// consent. Returned identities are observations; they grant no capture authority.
func (h *Host) CaptureWindows(ctx context.Context, requested auth.Principal, surface model.Surface, limit int) (native.CaptureWindowList, error) {
	p, err := h.capturePrincipal(ctx, requested, surface)
	if err != nil {
		return native.CaptureWindowList{}, err
	}
	if h.captureHelper == "" || h.captureWindows == nil {
		return native.CaptureWindowList{}, captureUnsupported("Native capture window discovery helper must be configured")
	}
	if limit < 1 || limit > native.MaximumCaptureWindows {
		return native.CaptureWindowList{}, errors.New("capture discovery requires a bounded window limit")
	}
	lease, err := h.AuthorizeOperation(ctx, p, surface, false, consent.Observe)
	if err != nil {
		return native.CaptureWindowList{}, err
	}
	if lease == nil || lease.Context == nil || lease.Release == nil {
		return native.CaptureWindowList{}, errors.New("complete capture discovery consent lease required")
	}
	ctx, cancel := context.WithCancel(lease.Context)
	defer cancel()
	result, err := h.captureWindows(ctx, native.CaptureWindowListOptions{HelperPath: h.captureHelper, BundleID: surface.BundleID, ProcessID: surface.ProcessID, ProcessStartToken: surface.ProcessStartToken, Limit: limit})
	if err != nil {
		var failure *native.CaptureError
		if errors.As(err, &failure) && failure.CleanupConfirmed {
			lease.Release()
		}
		return native.CaptureWindowList{}, err
	}
	lease.Release()
	return result, nil
}
