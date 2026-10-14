package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/png"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
)

func TestPlainCaptureRetiresOwnedUnusedFrameBeforeNewObservation(t *testing.T) {
	h, f, helper, ctx, surface := newWindowFrameHostFixture(t)
	h.captureHelper, h.captureMaxBytes = "fixture-readonly-capture", 1<<20
	var pixels bytes.Buffer
	if err := png.Encode(&pixels, image.NewNRGBA(image.Rect(0, 0, 16, 12))); err != nil {
		t.Fatal(err)
	}
	var old *windowFramePermit
	var captures atomic.Int32
	var discoveries atomic.Int32
	h.captureWindows = func(current context.Context, options native.CaptureWindowListOptions) (native.CaptureWindowList, error) {
		discoveries.Add(1)
		return native.CaptureWindowList{BundleID: options.BundleID, Windows: []native.CaptureWindowTarget{{BundleID: options.BundleID, PID: 42, ProcessStartToken: "100:1", WindowID: 17, Title: "Generic fixture"}}, ReturnedAt: time.Now().Format(time.RFC3339Nano)}, current.Err()
	}
	if _, err := h.CaptureWindows(ctx, f.principal, surface, 16); err != nil {
		t.Fatal("initial window discovery failed", err)
	}
	h.captureWindow = func(current context.Context, options native.WindowCaptureOptions) (native.CapturedImage, error) {
		// The native boundary cannot borrow a still-held control interval.
		// Drive the real Host/consent/manager transition rather than clearing
		// the permit or substituting an alternate authorization path.
		if old != nil {
			select {
			case <-old.done:
			case <-current.Done():
				return native.CapturedImage{}, &native.CaptureError{Cause: current.Err(), CleanupConfirmed: true, DispatchState: "notDispatched"}
			}
			f.mu.Lock()
			alive := f.alive
			f.mu.Unlock()
			if alive || old.cleanupErr != nil || old.lease.Context.Err() == nil || !old.retiring {
				return native.CapturedImage{}, errors.New("prior frame authority was not physically retired")
			}
		}
		captures.Add(1)
		return native.CapturedImage{PNG: pixels.Bytes(), Metadata: native.CaptureMetadata{BundleID: options.BundleID, PID: options.PID, ProcessStartToken: options.ProcessStartToken, WindowID: options.WindowID, Identity: fmt.Sprintf("window:%d", options.WindowID), Bytes: pixels.Len(), Width: 16, Height: 12}}, nil
	}
	if _, _, err := h.CaptureWindow(ctx, f.principal, surface, 42, 17); err != nil {
		t.Fatal("plain baseline failed", err)
	}
	imageRef, provenance, original, err := h.CaptureWindowFrame(ctx, f.principal, surface, 42, 17)
	if err != nil {
		t.Fatal(err)
	}
	h.frameMu.Lock()
	old = h.framePermits[f.principal.Namespace]
	h.frameMu.Unlock()
	if old == nil || !old.ready || old.used {
		t.Fatal("ready unused frame was not retained")
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, err := h.CaptureWindows(bounded, f.principal, surface, 16); err != nil || discoveries.Load() != 2 {
		t.Fatal("metadata-only discovery stranded behind retained frame", err)
	}
	h.frameMu.Lock()
	retained := h.framePermits[f.principal.Namespace] == old && old.ready && !old.used && !old.retiring && old.lease.Context.Err() == nil
	h.frameMu.Unlock()
	if !retained {
		t.Fatal("metadata-only discovery consumed the current frame")
	}
	ref, image, err := h.CaptureWindow(bounded, f.principal, surface, 42, 17)
	if err != nil || ref.ID == "" || !bytes.Equal(image.PNG, pixels.Bytes()) || captures.Load() != 2 {
		t.Fatal("ordinary capture stranded behind its own unused frame", err)
	}
	if err := h.artifacts.VerifyArtifact(ctx, f.principal, imageRef); err != nil {
		t.Fatal("retirement lost immutable image evidence", err)
	}
	if err := h.artifacts.VerifyArtifact(ctx, f.principal, provenance); err != nil {
		t.Fatal("retirement lost immutable provenance", err)
	}
	old = nil
	_, _, fresh, err := h.CaptureWindowFrame(ctx, f.principal, surface, 42, 17)
	if err != nil || fresh.Permit.ID == original.Permit.ID || fresh.Permit.FenceGeneration <= original.Permit.FenceGeneration || helper.clicks != 0 {
		t.Fatal("capture handoff consumed input or prevented fresh frame", err)
	}
}

func TestPlainCaptureCannotRetireForeignUsedCreatingOrUncertainFrame(t *testing.T) {
	for _, mode := range []string{"used", "creating", "retiring", "foreignClient", "foreignSession", "cleanupUnknown"} {
		t.Run(mode, func(t *testing.T) {
			h, f, helper, ctx, surface := newWindowFrameHostFixture(t)
			h.captureHelper, h.captureMaxBytes = "fixture-readonly-capture", 1<<20
			var captures atomic.Int32
			h.captureWindow = func(context.Context, native.WindowCaptureOptions) (native.CapturedImage, error) {
				captures.Add(1)
				return native.CapturedImage{}, errors.New("unsafe ordinary capture boundary reached")
			}
			if _, _, _, err := h.CaptureWindowFrame(ctx, f.principal, surface, 42, 17); err != nil {
				t.Fatal(err)
			}
			h.frameMu.Lock()
			old := h.framePermits[f.principal.Namespace]
			switch mode {
			case "used":
				old.used = true
			case "creating":
				old.ready = false
			case "retiring":
				old.retiring = true
			case "foreignClient":
				old.principal.ClientID = "another-client"
			case "foreignSession":
				old.binding.SessionID = "another-session"
			}
			h.frameMu.Unlock()
			if mode == "cleanupUnknown" {
				f.mu.Lock()
				f.unknown = true
				f.mu.Unlock()
			}
			_, _, err := h.CaptureWindow(ctx, f.principal, surface, 42, 17)
			if err == nil || captures.Load() != 0 || helper.clicks != 0 {
				t.Error("unsafe capture handoff reached a new native operation", err)
			}
			if mode == "cleanupUnknown" {
				var failure *native.CaptureError
				if !errors.As(err, &failure) || failure.CleanupConfirmed || failure.DispatchState != "notDispatched" || !errors.Is(err, ErrNativeControlCleanupUnknown) {
					t.Error("retained cleanup uncertainty was hidden", err)
				}
			} else {
				h.frameMu.Lock()
				preserved := h.framePermits[f.principal.Namespace] == old && old.lease.Context.Err() == nil
				h.frameMu.Unlock()
				f.mu.Lock()
				alive := f.alive
				f.mu.Unlock()
				if !preserved || !alive {
					t.Error("foreign or active owner was stopped or discarded")
				}
			}
			// Restore only fixture state so its ordinary cleanup can drain.
			h.frameMu.Lock()
			old.used, old.ready, old.retiring = false, true, false
			old.principal = f.principal
			old.binding, _ = auth.ConsentBindingFromContext(ctx)
			h.frameMu.Unlock()
			f.mu.Lock()
			f.unknown = false
			f.mu.Unlock()
		})
	}
}
