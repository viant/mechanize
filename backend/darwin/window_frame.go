package darwin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"math"
	"time"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

const MaximumWindowFrameBytes = MaximumCaptureBytes
const WindowFramePermitLifetime = 30 * time.Second

type WindowFrameOwner RecordingOwner

func (o WindowFrameOwner) Validate() error { return RecordingOwner(o).Validate() }

type WindowFramePermit struct {
	ID                string           `json:"id"`
	Owner             WindowFrameOwner `json:"owner"`
	HelperEpoch       string           `json:"helperEpoch"`
	FenceGeneration   uint64           `json:"fenceGeneration"`
	BundleID          string           `json:"bundleId"`
	PID               int              `json:"pid"`
	ProcessStartToken string           `json:"processStartToken"`
	WindowID          uint32           `json:"windowId"`
	DisplayID         uint32           `json:"displayId"`
	Bounds            CaptureBounds    `json:"bounds"`
	Width             int              `json:"widthPixels"`
	Height            int              `json:"heightPixels"`
	Scale             float64          `json:"scale"`
	ContentHash       string           `json:"contentHash"`
	CapturedAt        time.Time        `json:"capturedAt"`
	ExpiresAt         time.Time        `json:"expiresAt"`
}

type WindowFrameCapture struct {
	Permit WindowFramePermit `json:"permit"`
	PNG    []byte            `json:"-"`
}

func frameOwner(ctx context.Context, p auth.Principal) (WindowFrameOwner, error) {
	actual, err := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	owner := WindowFrameOwner{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: binding.SessionID}
	if err != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || !ok || owner.Validate() != nil || !p.HasScope("desktop:control") {
		return owner, auth.ErrUnauthorized
	}
	return owner, nil
}

func (g *Gateway) frameLease(ctx context.Context, p auth.Principal) (Lease, error) {
	if err := g.ready(ctx); err != nil {
		return Lease{}, err
	}
	if !g.axTrusted || !g.semanticEnabled || !g.windowFrameClickEnabled || g.options.Lease == nil {
		return Lease{}, nativeError("windowFrameUnqualified", "Explicit capture-bound window-click qualification required")
	}
	lease, err := g.options.Lease(ctx, p)
	if err != nil {
		return lease, err
	}
	if lease.ID == "" || lease.Generation == 0 {
		return lease, nativeError("invalidLease", "Exact held desktop fence required")
	}
	if lease != g.installed {
		if _, err = g.call(ctx, "lease.install", lease, nil); err != nil {
			return lease, err
		}
		g.installed = lease
	}
	return lease, nil
}

// CaptureWindowFrame uses the same qualified helper and fence as the subsequent
// click. Ordinary disposable screenshots cannot create this capability.
func (g *Gateway) CaptureWindowFrame(ctx context.Context, p auth.Principal, surface model.Surface, windowID uint32) (WindowFrameCapture, error) {
	if err := authorized(ctx, p, true); err != nil {
		return WindowFrameCapture{}, err
	}
	if err := g.surface(surface); err != nil {
		return WindowFrameCapture{}, err
	}
	if surface.ProcessID <= 0 || surface.ValidateProcessIdentity() != nil || windowID == 0 {
		return WindowFrameCapture{}, nativeError("invalidTarget", "Exact native process birth and physical window required")
	}
	owner, err := frameOwner(ctx, p)
	if err != nil {
		return WindowFrameCapture{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.framePermit != nil && time.Now().Before(g.framePermit.ExpiresAt) {
		return WindowFrameCapture{}, nativeError("framePermitActive", "One retained frame permit at a time")
	}
	lease, err := g.frameLease(ctx, p)
	if err != nil {
		return WindowFrameCapture{}, err
	}
	epoch := g.epoch
	started := time.Now()
	reply, err := g.call(ctx, "windows.captureFrame", map[string]any{"expectedApp": surface.BundleID, "pid": surface.ProcessID, "processStartToken": surface.ProcessStartToken, "windowId": windowID, "owner": owner}, &lease)
	received := time.Now()
	if err != nil {
		return WindowFrameCapture{}, err
	}
	var body struct {
		Permit    WindowFramePermit `json:"permit"`
		PNGBase64 string            `json:"pngBase64"`
	}
	decoder := json.NewDecoder(bytes.NewReader(reply.Result))
	decoder.DisallowUnknownFields()
	if len(reply.Result) > MaximumWindowFrameResponseBytes || decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF || len(body.PNGBase64) > base64.StdEncoding.EncodedLen(MaximumWindowFrameBytes) {
		return WindowFrameCapture{}, nativeError("frameEvidenceMismatch", "Bounded closed capture reply required")
	}
	image, err := base64.StdEncoding.Strict().DecodeString(body.PNGBase64)
	frame := WindowFrameCapture{Permit: body.Permit, PNG: image}
	if err != nil || ctx.Err() != nil || reply.HelperEpoch != epoch || reply.RequestID == "" || reply.Receipt != nil || ValidateWindowFrameCapture(frame, surface, windowID, owner, epoch, lease.Generation, started, received) != nil {
		return WindowFrameCapture{}, nativeError("frameEvidenceMismatch", "Capture identity, frame mapping, bytes or receipt interval changed")
	}
	permit := frame.Permit
	g.framePermit = &permit
	return frame, nil
}

func ValidateWindowFrameCapture(frame WindowFrameCapture, surface model.Surface, windowID uint32, owner WindowFrameOwner, epoch string, generation uint64, started, received time.Time) error {
	p := frame.Permit
	sum := sha256.Sum256(frame.PNG)
	finite := func(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
	if owner.Validate() != nil || !recordingBounded(p.ID, 256) || p.Owner != owner || p.HelperEpoch == "" || p.HelperEpoch != epoch || p.FenceGeneration == 0 || p.FenceGeneration != generation || p.BundleID != surface.BundleID || p.PID != surface.ProcessID || p.ProcessStartToken != surface.ProcessStartToken || !model.ValidProcessStartToken(p.ProcessStartToken) || p.WindowID != windowID || windowID == 0 || p.DisplayID == 0 || len(frame.PNG) == 0 || len(frame.PNG) > MaximumWindowFrameBytes || p.ContentHash != hex.EncodeToString(sum[:]) || !windowKeyTimeQualified(p.CapturedAt, started, received) || p.ExpiresAt.Sub(p.CapturedAt) != WindowFramePermitLifetime || !p.ExpiresAt.After(received) {
		return errors.New("capture permit identity/hash/freshness mismatch")
	}
	if p.Width <= 0 || p.Height <= 0 || p.Width > 32768 || p.Height > 32768 || int64(p.Width)*int64(p.Height) > 32_000_000 || !finite(p.Scale) || p.Scale <= 0 || p.Scale > 8 || !finite(p.Bounds.X) || !finite(p.Bounds.Y) || !finite(p.Bounds.Width) || !finite(p.Bounds.Height) || p.Bounds.Width <= 0 || p.Bounds.Height <= 0 || math.Abs(p.Bounds.Width*p.Scale-float64(p.Width)) > 1 || math.Abs(p.Bounds.Height*p.Scale-float64(p.Height)) > 1 {
		return errors.New("capture permit coordinate mapping mismatch")
	}
	config, err := png.DecodeConfig(bytes.NewReader(frame.PNG))
	if err != nil || config.Width != p.Width || config.Height != p.Height {
		return errors.New("capture permit PNG dimensions mismatch")
	}
	return nil
}

func (g *Gateway) clickWindowFrame(ctx context.Context, p auth.Principal, step model.Step, bindings map[string]model.Value) (integration.StepResult, error) {
	result := integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	args, err := step.ResolveArguments(bindings)
	if err != nil {
		return result, err
	}
	ref, x, y, err := model.WindowFrameClick(args["frameClick"])
	if err != nil {
		return result, err
	}
	owner, err := frameOwner(ctx, p)
	if err != nil {
		return result, err
	}
	lease, err := g.frameLease(ctx, p)
	if err != nil {
		return result, err
	}
	permit := g.framePermit
	if permit == nil || permit.ID != ref || permit.Owner != owner || permit.HelperEpoch != g.epoch || permit.FenceGeneration != lease.Generation || permit.BundleID != step.Target.Surface.BundleID || permit.PID != step.Target.Surface.ProcessID || permit.ProcessStartToken != step.Target.Surface.ProcessStartToken || !time.Now().Before(permit.ExpiresAt) || x >= int64(permit.Width) || y >= int64(permit.Height) {
		return result, nativeError("staleFramePermit", "Fresh exact one-use captured frame and in-frame pixels required")
	}
	g.framePermit = nil // No mutation request is replayed, including uncertain transport.
	epoch := g.epoch
	started := time.Now()
	reply, err := g.call(ctx, "windows.clickFrame", map[string]any{"expectedApp": permit.BundleID, "pid": permit.PID, "processStartToken": permit.ProcessStartToken, "owner": owner, "permitId": permit.ID, "x": x, "y": y}, &lease)
	received := time.Now()
	if reply.Receipt != nil {
		result.DispatchState = reply.Receipt.DispatchState
	} else {
		var transport *TransportError
		var failure *NativeError
		if errors.As(err, &transport) {
			result.DispatchState = transport.DispatchState
		} else if errors.As(err, &failure) && failure.DispatchState != "" {
			result.DispatchState = failure.DispatchState
		} else if err == nil {
			result.DispatchState = "unknown"
		}
	}
	if result.DispatchState == "dispatched" {
		var proof struct {
			PermitID string           `json:"permitId"`
			Owner    WindowFrameOwner `json:"owner"`
			PID      int              `json:"pid"`
			Birth    string           `json:"startToken"`
			Bundle   string           `json:"bundleID"`
			WindowID uint32           `json:"windowId"`
			Identity string           `json:"identity"`
			Point    struct {
				X int64 `json:"x"`
				Y int64 `json:"y"`
			} `json:"point"`
			RequestID       string    `json:"requestId"`
			ObservedAt      time.Time `json:"observedAt"`
			BusinessSuccess *bool     `json:"businessSuccess"`
		}
		target := fmt.Sprintf("window:%d", permit.WindowID)
		decoder := json.NewDecoder(bytes.NewReader(reply.Result))
		decoder.DisallowUnknownFields()
		if err != nil || ctx.Err() != nil || len(reply.Result) > 4096 || decoder.Decode(&proof) != nil || decoder.Decode(new(any)) != io.EOF || proof.PermitID != permit.ID || proof.Owner != owner || proof.PID != permit.PID || proof.Birth != permit.ProcessStartToken || proof.Bundle != permit.BundleID || proof.WindowID != permit.WindowID || proof.Identity != target || proof.Point.X != x || proof.Point.Y != y || proof.RequestID == "" || proof.RequestID != reply.RequestID || proof.BusinessSuccess == nil || *proof.BusinessSuccess || reply.HelperEpoch != epoch || reply.Receipt.TargetRef != target || !windowKeyTimeQualified(proof.ObservedAt, started, received) {
			result.DispatchState = "unknown"
		}
	}
	if result.DispatchState == "unknown" || result.DispatchState != "dispatched" && result.DispatchState != "notDispatched" {
		result.DispatchState = "unknown"
		err = errors.Join(err, &model.MechanizeError{Code: "windowFrameUnconfirmed", Stage: "native", DispatchState: "unknown", EffectState: "unknown", Message: "Window frame click receipt unconfirmed; reconcile before replay"})
	}
	return result, err
}
