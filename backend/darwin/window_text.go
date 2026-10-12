package darwin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"io"
	"time"
)

// Text receipts prove dispatch correlation only; callers must verify the result.
func (g *Gateway) typeWindowText(ctx context.Context, p auth.Principal, step model.Step, bindings map[string]model.Value) (integration.StepResult, error) {
	result := integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	arguments, err := step.ResolveArguments(bindings)
	if err != nil {
		return result, err
	}
	input, err := model.WindowText(arguments["windowText"])
	windowID := input.WindowID
	if err != nil {
		return result, err
	}
	if err = g.ready(ctx); err != nil {
		return result, err
	}
	if !g.axTrusted || !(g.semanticEnabled || g.mutationEnabled) || !g.sessionTextEnabled || !g.windowSessionTextEnabled {
		return result, nativeError("windowTextUnqualified", fmt.Sprintf("Window text readiness failed: accessibility=%t semantic=%t mutation=%t sessionText=%t windowTextAdvertised=%t", g.axTrusted, g.semanticEnabled, g.mutationEnabled, g.sessionTextEnabled, g.windowSessionTextEnabled))
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
	reply, err := g.call(ctx, "windows.typeText", map[string]any{"expectedApp": step.Target.Surface.BundleID, "pid": step.Target.Surface.ProcessID, "processStartToken": step.Target.Surface.ProcessStartToken, "windowId": windowID, "text": input.Text, "focusRole": input.FocusRole, "focusIdentifier": input.FocusIdentifier, "focusName": input.FocusName}, &lease)
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
			err = &model.MechanizeError{Code: "windowTextUnconfirmed", Stage: "native", DispatchState: "unknown", EffectState: "unknown", Message: "Window text receipt is unconfirmed; reconcile before replay"}
		}
	}
	if result.DispatchState == "dispatched" {
		var proof struct {
			PID             int       `json:"pid"`
			Birth           string    `json:"startToken"`
			Bundle          string    `json:"bundleID"`
			WindowID        uint32    `json:"windowId"`
			Identity        string    `json:"identity"`
			TextHash        string    `json:"textHash"`
			FocusRole       string    `json:"focusRole"`
			FocusIdentifier string    `json:"focusIdentifier"`
			FocusName       string    `json:"focusName"`
			RequestID       string    `json:"requestId"`
			ObservedAt      time.Time `json:"observedAt"`
			BusinessSuccess *bool     `json:"businessSuccess"`
			InputSemantics  string    `json:"inputSemantics"`
		}
		target := fmt.Sprintf("window:%d", windowID)
		decoder := json.NewDecoder(bytes.NewReader(reply.Result))
		decoder.DisallowUnknownFields()
		if err != nil || ctx.Err() != nil || len(reply.Result) > 4096 || decoder.Decode(&proof) != nil || decoder.Decode(new(any)) != io.EOF || proof.PID != step.Target.Surface.ProcessID || proof.Birth != step.Target.Surface.ProcessStartToken || proof.Bundle != step.Target.Surface.BundleID || proof.WindowID != windowID || proof.Identity != target || proof.TextHash != fmt.Sprintf("%x", sha256.Sum256([]byte(input.Text))) || proof.FocusRole != input.FocusRole || proof.FocusIdentifier != input.FocusIdentifier || proof.FocusName != input.FocusName || proof.RequestID == "" || proof.RequestID != reply.RequestID || proof.BusinessSuccess == nil || *proof.BusinessSuccess || reply.HelperEpoch == "" || reply.HelperEpoch != expectedEpoch || reply.Receipt.TargetRef != target || !windowKeyTimeQualified(proof.ObservedAt, started, received) {
			result.DispatchState = "unknown"
			reason := "Window text receipt metadata is unconfirmed; reconcile before replay"
			if !proof.ObservedAt.IsZero() && !windowKeyTimeQualified(proof.ObservedAt, started, received) {
				reason = "Window text receipt timestamp is outside the millisecond-precision interval; reconcile before replay"
			}
			err = errors.Join(err, &model.MechanizeError{Code: "windowTextUnconfirmed", Stage: "native", DispatchState: "unknown", EffectState: "unknown", Message: reason})
		}
	}
	return result, err
}
