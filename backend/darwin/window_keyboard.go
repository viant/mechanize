package darwin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"io"
	"time"
)

// pressWindowKey performs no app/window/element AX snapshot. The helper must
// independently qualify the exact fresh CGWindow and foreground session.
func (g *Gateway) pressWindowKey(ctx context.Context, p auth.Principal, step model.Step, bindings map[string]model.Value) (integration.StepResult, error) {
	result := integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	arguments, err := step.ResolveArguments(bindings)
	if err != nil {
		return result, err
	}
	windowID, key, err := model.WindowSessionKey(arguments["windowKey"])
	if err != nil {
		return result, err
	}
	if err = g.ready(ctx); err != nil {
		return result, err
	}
	if !g.axTrusted || !(g.semanticEnabled || g.mutationEnabled) || !g.sessionKeyboardEnabled || !g.windowSessionKeyboardEnabled {
		return result, nativeError("windowKeyboardUnqualified", "Advertised window route and explicit session keyboard opt-in required")
	}
	if g.options.Lease == nil {
		return result, nativeError("leaseUnavailable", "External desktop fence required")
	}
	lease, err := g.options.Lease(ctx, p)
	if err != nil {
		return result, err
	}
	if lease.ID == "" || lease.Generation == 0 {
		return result, nativeError("invalidLease", "Exact held desktop fence required")
	}
	if lease != g.installed {
		if _, err = g.call(ctx, "lease.install", lease, nil); err != nil {
			return result, err
		}
		g.installed = lease
	}
	expectedEpoch := g.epoch
	started := time.Now()
	reply, err := g.call(ctx, "windows.pressSessionKey", map[string]any{"expectedApp": step.Target.Surface.BundleID, "pid": step.Target.Surface.ProcessID, "processStartToken": step.Target.Surface.ProcessStartToken, "windowId": windowID, "key": key}, &lease)
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
			err = &model.MechanizeError{Code: "windowKeyUnconfirmed", Stage: "native", DispatchState: "unknown", EffectState: "unknown", Message: "Window key receipt is unconfirmed; reconcile before replay"}
		}
	}
	if result.DispatchState == "dispatched" {
		var proof struct {
			PID             int       `json:"pid"`
			Birth           string    `json:"startToken"`
			Bundle          string    `json:"bundleID"`
			WindowID        uint32    `json:"windowId"`
			Identity        string    `json:"identity"`
			Key             string    `json:"key"`
			RequestID       string    `json:"requestId"`
			ObservedAt      time.Time `json:"observedAt"`
			BusinessSuccess *bool     `json:"businessSuccess"`
			InputSemantics  string    `json:"inputSemantics"`
		}
		target := fmt.Sprintf("window:%d", windowID)
		decoder := json.NewDecoder(bytes.NewReader(reply.Result))
		decoder.DisallowUnknownFields()
		if err != nil || ctx.Err() != nil || len(reply.Result) > 4096 || decoder.Decode(&proof) != nil || decoder.Decode(new(any)) != io.EOF || proof.PID != step.Target.Surface.ProcessID || proof.Birth != step.Target.Surface.ProcessStartToken || proof.Bundle != step.Target.Surface.BundleID || proof.WindowID != windowID || proof.Identity != target || proof.Key != key || proof.RequestID == "" || proof.RequestID != reply.RequestID || proof.BusinessSuccess == nil || *proof.BusinessSuccess || reply.HelperEpoch == "" || reply.HelperEpoch != expectedEpoch || reply.Receipt.TargetRef != target || !windowKeyTimeQualified(proof.ObservedAt, started, received) {
			result.DispatchState = "unknown"
			reason := "Window key receipt metadata is unconfirmed; reconcile before replay"
			if !proof.ObservedAt.IsZero() && !windowKeyTimeQualified(proof.ObservedAt, started, received) {
				reason = "Window key receipt timestamp is outside the millisecond-precision interval; reconcile before replay"
			}
			err = errors.Join(err, &model.MechanizeError{Code: "windowKeyUnconfirmed", Stage: "native", DispatchState: "unknown", EffectState: "unknown", Message: reason})
		}
	}
	return result, err
}

// ISO8601DateFormatter rounds the native timestamp to milliseconds. Account
// for that precision at both interval endpoints, without extending read freshness.
func windowKeyTimeQualified(observed, started, received time.Time) bool {
	return !observed.IsZero() && !received.Before(started) &&
		!observed.Before(started.Add(-time.Millisecond)) &&
		!observed.After(received.Add(time.Millisecond)) && received.Sub(observed) <= 3*time.Second
}
