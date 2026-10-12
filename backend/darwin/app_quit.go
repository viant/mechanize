package darwin

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func containsMethod(methods []string, expected string) bool {
	for _, method := range methods {
		if method == expected {
			return true
		}
	}
	return false
}

func (g *Gateway) quitApp(ctx context.Context, p auth.Principal, step model.Step) (integration.StepResult, error) {
	result := integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	if err := g.ready(ctx); err != nil {
		return result, err
	}
	if !g.quitEnabled {
		return result, nativeError("mutationDisabled", "Helper must advertise normal quit and exact exit observation")
	}
	if g.options.Lease == nil {
		return result, nativeError("leaseUnavailable", "External desktop fence required")
	}
	app, err := g.currentApplication(ctx, step.Target.Surface)
	if err != nil {
		return result, err
	}
	lease, err := g.options.Lease(ctx, p)
	if err != nil {
		return result, err
	}
	if lease.ID == "" || lease.Generation == 0 {
		return result, nativeError("invalidLease", "Held external fence absent")
	}
	if lease != g.installed {
		reply, installErr := g.call(ctx, "lease.install", lease, nil)
		if installErr != nil || reply.Error != nil {
			return result, errors.Join(installErr, reply.Error)
		}
		g.installed = lease
	}
	params := map[string]any{"expectedApp": app.BundleID, "pid": app.PID, "launchTime": app.LaunchTime, "startToken": app.StartToken}
	// A lifecycle request burns any prior capture authority even if its transport
	// outcome is unknown. The native helper separately invalidates AX references.
	g.framePermit = nil
	reply, err := g.call(ctx, "app.quit", params, &lease)
	if reply.Receipt != nil {
		result.DispatchState = reply.Receipt.DispatchState
	} else {
		var transport *TransportError
		if errors.As(err, &transport) && transport.DispatchState == "notDispatched" {
			result.DispatchState = "notDispatched"
		} else {
			result.DispatchState = "unknown"
		}
	}
	unknown := func(message string) (integration.StepResult, error) {
		result.DispatchState = "unknown"
		return result, &model.MechanizeError{Code: "quitPostconditionUnknown", Stage: "verification", DispatchState: "unknown", EffectState: "unknown", Message: message}
	}
	if err != nil || reply.Error != nil {
		if result.DispatchState == "notDispatched" {
			return result, errors.Join(err, reply.Error)
		}
		return unknown("Quit may have been submitted; reconcile before replay")
	}
	if result.DispatchState != "dispatched" {
		return unknown("Quit receipt unavailable; reconcile before replay")
	}
	var confirmation struct {
		applicationIdentity
		QuitRequested bool `json:"quitRequested"`
		ExitConfirmed bool `json:"exitConfirmed"`
	}
	if json.Unmarshal(reply.Result, &confirmation) != nil || !confirmation.QuitRequested || !confirmation.ExitConfirmed || confirmation.BundleID != app.BundleID || confirmation.PID != app.PID || confirmation.StartToken != app.StartToken || confirmation.LaunchTime != app.LaunchTime {
		return unknown("Normal quit lacks exact process exit confirmation; reconcile before replay")
	}
	observed, observeErr := g.call(ctx, "app.exitStatus", params, nil)
	var status struct {
		applicationIdentity
		ExitConfirmed        bool `json:"exitConfirmed"`
		ObservationAvailable bool `json:"observationAvailable"`
	}
	if observeErr != nil || observed.Error != nil || json.Unmarshal(observed.Result, &status) != nil || !status.ObservationAvailable || !status.ExitConfirmed || status.BundleID != app.BundleID || status.PID != app.PID || status.StartToken != app.StartToken || status.LaunchTime != app.LaunchTime {
		return unknown("Independent exact process observation did not prove exit; reconcile before replay")
	}
	result.VerificationState = "verified"
	return result, nil
}
