package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

type ProcessExitObservation struct {
	ExitConfirmed bool
	HelperEpoch   string
	TargetRef     string
	ObservedAt    time.Time
}

// ProcessExit reads the original PID/birth directly. It neither inventories a
// replacement app nor borrows a control helper whose uncertain input is fenced.
func (g *Gateway) ProcessExit(ctx context.Context, p auth.Principal, surface model.Surface) (ProcessExitObservation, error) {
	if err := authorized(ctx, p, false); err != nil {
		return ProcessExitObservation{}, err
	}
	if err := g.surface(surface); err != nil {
		return ProcessExitObservation{}, err
	}
	if surface.ProcessID <= 0 || surface.ValidateProcessIdentity() != nil {
		return ProcessExitObservation{}, nativeError("processIdentityRequired", "Original PID and kernel birth required")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.ready(ctx); err != nil {
		return ProcessExitObservation{}, err
	}
	if !g.processExitEnabled {
		return ProcessExitObservation{}, nativeError("unsupported", "Exact process exit observation is not advertised")
	}
	reply, err := g.call(ctx, "app.exitStatus", map[string]any{"expectedApp": surface.BundleID, "pid": surface.ProcessID, "launchTime": "kernel:" + surface.ProcessStartToken, "startToken": surface.ProcessStartToken}, nil)
	if err != nil || reply.Error != nil {
		return ProcessExitObservation{}, errors.Join(err, reply.Error)
	}
	var status struct {
		applicationIdentity
		ExitConfirmed        bool `json:"exitConfirmed"`
		ObservationAvailable bool `json:"observationAvailable"`
	}
	if json.Unmarshal(reply.Result, &status) != nil || !status.ObservationAvailable || status.BundleID != surface.BundleID || status.PID != surface.ProcessID || status.StartToken != surface.ProcessStartToken || status.LaunchTime != "kernel:"+surface.ProcessStartToken || reply.HelperEpoch == "" || reply.Receipt != nil {
		return ProcessExitObservation{}, nativeError("incompleteObservation", "Exact independent process evidence unavailable")
	}
	if err := ctx.Err(); err != nil {
		return ProcessExitObservation{}, err
	}
	return ProcessExitObservation{ExitConfirmed: status.ExitConfirmed, HelperEpoch: reply.HelperEpoch, TargetRef: fmt.Sprintf("process:%d:%s", surface.ProcessID, surface.ProcessStartToken), ObservedAt: time.Now()}, nil
}
