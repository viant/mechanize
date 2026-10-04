package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

type applicationIdentity struct {
	BundleID   string `json:"bundleID"`
	PID        int    `json:"pid"`
	LaunchTime string `json:"launchTime"`
	StartToken string `json:"startToken"`
	Active     bool   `json:"active"`
}

func (g *Gateway) currentApplication(ctx context.Context, surface model.Surface) (applicationIdentity, error) {
	reply, err := g.call(ctx, "apps.list", map[string]any{"expectedApp": surface.BundleID}, nil)
	if err != nil || reply.Error != nil {
		return applicationIdentity{}, errors.Join(err, reply.Error)
	}
	var inventory struct {
		Complete bool                  `json:"complete"`
		Apps     []applicationIdentity `json:"apps"`
	}
	if json.Unmarshal(reply.Result, &inventory) != nil || !inventory.Complete {
		return applicationIdentity{}, nativeError("incompleteObservation", "Exact application inventory is incomplete")
	}
	var matches []applicationIdentity
	for _, app := range inventory.Apps {
		if app.BundleID == surface.BundleID && (surface.ProcessID == 0 || (app.PID == surface.ProcessID && app.StartToken == surface.ProcessStartToken)) {
			matches = append(matches, app)
		}
	}
	if len(matches) != 1 {
		code := "ambiguousTarget"
		if surface.ProcessID != 0 {
			code = "staleReference"
		}
		return applicationIdentity{}, nativeError(code, fmt.Sprintf("Expected one application, found %d", len(matches)))
	}
	app := matches[0]
	if app.PID <= 0 || app.LaunchTime == "" || app.StartToken == "" {
		return applicationIdentity{}, nativeError("appIdentityUnavailable", "Complete application identity required")
	}
	return app, nil
}
func (g *Gateway) activateApp(ctx context.Context, p auth.Principal, step model.Step) (integration.StepResult, error) {
	result := integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	if err := g.ready(ctx); err != nil {
		return result, err
	}
	if !g.axTrusted || !(g.semanticEnabled || g.mutationEnabled) {
		return result, nativeError("mutationDisabled", "Semantic or full native authority and AX trust required for activation")
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
		if _, err = g.call(ctx, "lease.install", lease, nil); err != nil {
			return result, err
		}
		g.installed = lease
	}
	reply, err := g.call(ctx, "app.activate", map[string]any{"expectedApp": app.BundleID, "pid": app.PID, "launchTime": app.LaunchTime, "startToken": app.StartToken}, &lease)
	if reply.Receipt != nil {
		result.DispatchState = reply.Receipt.DispatchState
	} else {
		var transport *TransportError
		if errors.As(err, &transport) {
			result.DispatchState = transport.DispatchState
		} else if err == nil {
			result.DispatchState = "unknown"
		}
	}
	if err != nil || reply.Error != nil {
		return result, errors.Join(err, reply.Error)
	}
	if result.DispatchState != "dispatched" {
		return result, nativeError("activationOutcomeUnknown", "Activation receipt unavailable; reconcile before replay")
	}
	current, err := g.currentApplication(ctx, step.Target.Surface)
	if err != nil || current.PID != app.PID || current.LaunchTime != app.LaunchTime || current.StartToken != app.StartToken || !current.Active {
		result.DispatchState = "unknown"
		return result, errors.Join(err, &model.MechanizeError{Code: "activationPostconditionUnknown", Stage: "verification", DispatchState: "unknown", EffectState: "unknown", Message: "Independent exact application observation did not prove active identity; reconcile before replay"})
	}
	result.VerificationState = "verified"
	return result, nil
}
