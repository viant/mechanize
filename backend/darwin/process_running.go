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

type ProcessRunningObservation struct {
	Running     bool
	HelperEpoch string
	TargetRef   string
	ObservedAt  time.Time
}

// ProcessRunning compares a complete independent inventory with the original
// launch receipt. A replacement process, even of the same bundle, cannot match.
func (g *Gateway) ProcessRunning(ctx context.Context, p auth.Principal, surface model.Surface) (ProcessRunningObservation, error) {
	if err := authorized(ctx, p, false); err != nil {
		return ProcessRunningObservation{}, err
	}
	if err := g.surface(surface); err != nil {
		return ProcessRunningObservation{}, err
	}
	if surface.ProcessID <= 0 || surface.ValidateProcessIdentity() != nil {
		return ProcessRunningObservation{}, nativeError("processIdentityRequired", "Original launch receipt PID and kernel birth required")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.ready(ctx); err != nil {
		return ProcessRunningObservation{}, err
	}
	reply, err := g.applicationInventory(ctx, surface)
	if err != nil || reply.Error != nil {
		return ProcessRunningObservation{}, errors.Join(err, reply.Error)
	}
	var inventory struct {
		Complete bool                  `json:"complete"`
		Apps     []applicationIdentity `json:"apps"`
	}
	if json.Unmarshal(reply.Result, &inventory) != nil || !inventory.Complete || reply.HelperEpoch == "" || reply.Receipt != nil {
		return ProcessRunningObservation{}, nativeError("incompleteObservation", "Complete independent application inventory required")
	}
	matches, instances := 0, 0
	for _, app := range inventory.Apps {
		if app.BundleID == surface.BundleID {
			instances++
		}
		if app.BundleID == surface.BundleID && app.PID == surface.ProcessID && app.StartToken == surface.ProcessStartToken && app.LaunchTime == "kernel:"+surface.ProcessStartToken {
			matches++
		}
	}
	if err := ctx.Err(); err != nil {
		return ProcessRunningObservation{}, err
	}
	return ProcessRunningObservation{Running: matches == 1 && instances == 1, HelperEpoch: reply.HelperEpoch, TargetRef: fmt.Sprintf("process:%d:%s", surface.ProcessID, surface.ProcessStartToken), ObservedAt: time.Now()}, nil
}
