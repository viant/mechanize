package darwin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"regexp"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

// Begin owners use a fresh token for each operation; tokens are not replay keys.
// ControlBadgeTarget is trusted broker metadata, never a page-content target.
type ControlBadgeTarget struct {
	BundleID          string
	ProcessID         int
	ProcessStartToken string
	WindowBounds      CaptureBounds
}
type ControlBadgeResult struct {
	Status string `json:"status"`
}

var badgeTokenPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (g *Gateway) BeginControlBadge(ctx context.Context, p auth.Principal, token string, target ControlBadgeTarget, duration time.Duration) (ControlBadgeResult, error) {
	surface := model.Surface{Kind: "native", BundleID: target.BundleID, ProcessID: target.ProcessID, ProcessStartToken: target.ProcessStartToken}
	b := target.WindowBounds
	if g == nil || g.surface(surface) != nil || target.ProcessID <= 0 || !finiteBadgeBounds(b) {
		return ControlBadgeResult{Status: "unavailable"}, nativeError("badgeUnavailable", "Presentation scope unavailable")
	}
	params := map[string]any{"token": token, "expectedApp": target.BundleID, "pid": target.ProcessID, "processStartToken": target.ProcessStartToken, "windowBounds": b, "durationMs": duration.Milliseconds()}
	if session := presentationSession(ctx); session != "" {
		params["sessionToken"] = session
	}
	return g.controlBadge(ctx, p, "controlBadge.begin", token, duration, params)
}
func finiteBadgeBounds(b CaptureBounds) bool {
	for _, v := range []float64{b.X, b.Y, b.Width, b.Height} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return false
		}
	}
	return b.Width >= 120 && b.Height >= 48
}
func (g *Gateway) RenewControlBadge(ctx context.Context, p auth.Principal, token string, duration time.Duration) (ControlBadgeResult, error) {
	return g.controlBadge(ctx, p, "controlBadge.renew", token, duration, map[string]any{"token": token, "durationMs": duration.Milliseconds()})
}
func (g *Gateway) EndControlBadge(ctx context.Context, p auth.Principal, token string) (ControlBadgeResult, error) {
	return g.controlBadge(ctx, p, "controlBadge.end", token, 0, map[string]any{"token": token})
}
func (g *Gateway) StopControlBadge(ctx context.Context, p auth.Principal, token string) (ControlBadgeResult, error) {
	return g.controlBadge(ctx, p, "controlBadge.stop", token, 0, map[string]any{"token": token})
}
func (g *Gateway) controlBadge(ctx context.Context, p auth.Principal, method, token string, duration time.Duration, params any) (ControlBadgeResult, error) {
	unavailable := ControlBadgeResult{Status: "unavailable"}
	actual, e := auth.FromContext(ctx)
	if g == nil || e != nil || authorized(ctx, p, false) != nil || p.ClientID == "" || actual.ClientID != p.ClientID || !badgeTokenPattern.MatchString(token) || (method != "controlBadge.end" && method != "controlBadge.stop" && method != "controlBadge.releaseSession" && (duration < 100*time.Millisecond || duration > 5*time.Second)) {
		return unavailable, nativeError("badgeUnavailable", "Presentation scope unavailable")
	}
	queueBudget := time.Second
	if method == "controlBadge.releaseSession" {
		queueBudget = 35 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, queueBudget)
	defer cancel()
	for !g.mu.TryLock() {
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return unavailable, ctx.Err()
		case <-timer.C:
		}
	}
	defer g.mu.Unlock()
	if ctx.Err() != nil {
		return unavailable, ctx.Err()
	}
	callCtx, stopCall := context.WithTimeout(ctx, time.Second)
	defer stopCall()
	ctx = callCtx
	skipRefresh := false
	if method == "controlBadge.releaseSession" {
		_, skipRefresh = g.caller.(interface {
			PrepareRead(context.Context) (uint64, error)
		})
		if skipRefresh && g.epoch == "" {
			return unavailable, nativeError("badgeUnavailable", "Presentation connection unavailable")
		}
	}
	if !skipRefresh && g.ready(ctx) != nil {
		return unavailable, nativeError("badgeUnavailable", "Presentation unavailable")
	}
	data, e := json.Marshal(params)
	if e != nil {
		return unavailable, e
	}
	remaining := int64(1000)
	if deadline, ok := ctx.Deadline(); ok {
		remaining = time.Until(deadline).Milliseconds()
	}
	if remaining <= 0 {
		return unavailable, ctx.Err()
	}
	reply, e := g.caller.Call(ctx, Request{ProtocolVersion: 1, RequestID: requestID(), Method: method, HelperEpoch: g.epoch, DeadlineRemainingMS: remaining, Params: data})
	if e != nil || reply.Error != nil || reply.HelperEpoch != g.epoch || ctx.Err() != nil {
		return unavailable, nativeError("badgeUnavailable", "Presentation unavailable")
	}
	var result ControlBadgeResult
	decoder := json.NewDecoder(bytes.NewReader(reply.Result))
	decoder.DisallowUnknownFields()
	if len(reply.Result) > 128 || decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || (result.Status != "shown" && result.Status != "hidden" && result.Status != "unavailable" && result.Status != "placementUnavailable") {
		return unavailable, nativeError("badgeUnavailable", "Presentation unavailable")
	}
	return result, nil
}

// Presentation ownership is derived from an already admitted Runtime session.
// It is not an input grant and reveals no raw principal/session identifiers.
func badgeSessionToken(p auth.Principal, sessionID string) string {
	if p.Namespace == "" || p.ClientID == "" || sessionID == "" || len(sessionID) > 128 {
		return ""
	}
	raw, _ := json.Marshal([]string{"mechanize-presentation-v1", p.Namespace, p.ClientID, sessionID})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
func presentationSession(ctx context.Context) string {
	p, e := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if e != nil || !ok {
		return ""
	}
	return badgeSessionToken(p, binding.SessionID)
}
func (g *Gateway) ReleaseControlBadgeSession(ctx context.Context, p auth.Principal, sessionID string) (ControlBadgeResult, error) {
	token := badgeSessionToken(p, sessionID)
	return g.controlBadge(ctx, p, "controlBadge.releaseSession", token, 0, map[string]any{"sessionToken": token})
}
