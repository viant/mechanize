package darwin

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

// ApplicationPresence is metadata, not foreground or document readiness.
// notObserved means absent from this complete inventory, not proven OS exit.
type ApplicationPresence struct {
	BundleID          string    `json:"bundleId"`
	State             string    `json:"state"`
	ProcessID         int       `json:"processId,omitempty"`
	ProcessStartToken string    `json:"processStartToken,omitempty"`
	ObservedAt        time.Time `json:"observedAt"`
}

func decodePresenceInventory(reply Reply, bundle string) ([]applicationIdentity, error) {
	var inventory struct {
		Complete *bool                  `json:"complete"`
		Apps     *[]applicationIdentity `json:"apps"`
	}
	if reply.Error != nil {
		return nil, reply.Error
	}
	if reply.HelperEpoch == "" || reply.Receipt != nil || json.Unmarshal(reply.Result, &inventory) != nil || inventory.Complete == nil || !*inventory.Complete || inventory.Apps == nil || len(*inventory.Apps) > 512 {
		return nil, nativeError("incompleteObservation", "Complete authenticated application inventory required")
	}
	seen := map[int]bool{}
	for _, app := range *inventory.Apps {
		identity := model.Surface{Kind: "native", BundleID: bundle, ProcessID: app.PID, ProcessStartToken: app.StartToken}
		if app.BundleID != bundle || app.PID <= 0 || identity.ValidateProcessIdentity() != nil || app.LaunchTime != "kernel:"+app.StartToken || seen[app.PID] {
			return nil, nativeError("incompleteObservation", "Exact unique process identities required")
		}
		seen[app.PID] = true
	}
	return *inventory.Apps, nil
}

func (g *Gateway) ApplicationPresence(ctx context.Context, p auth.Principal, surface model.Surface) (ApplicationPresence, error) {
	if err := authorized(ctx, p, false); err != nil {
		return ApplicationPresence{}, err
	}
	if err := g.surface(surface); err != nil {
		return ApplicationPresence{}, err
	}
	if surface.ProcessID != 0 || surface.ProcessStartToken != "" {
		return ApplicationPresence{}, nativeError("invalidScope", "Application discovery requires an unpinned exact bundle")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.ready(ctx); err != nil {
		return ApplicationPresence{}, err
	}
	reply, err := g.applicationInventory(ctx, surface)
	if err != nil {
		return ApplicationPresence{}, err
	}
	apps, err := decodePresenceInventory(reply, surface.BundleID)
	if err != nil {
		return ApplicationPresence{}, err
	}
	result := ApplicationPresence{BundleID: surface.BundleID, State: "notObserved"}
	if len(apps) > 1 {
		result.State = "ambiguous"
	} else if len(apps) == 1 {
		app := apps[0]
		pinned := surface
		pinned.ProcessID, pinned.ProcessStartToken = app.PID, app.StartToken
		fresh, readErr := g.applicationInventory(ctx, pinned)
		if readErr != nil {
			return ApplicationPresence{}, readErr
		}
		current, decodeErr := decodePresenceInventory(fresh, surface.BundleID)
		if decodeErr != nil {
			return ApplicationPresence{}, decodeErr
		}
		if fresh.HelperEpoch != reply.HelperEpoch || len(current) != 1 || current[0].PID != app.PID || current[0].StartToken != app.StartToken {
			return ApplicationPresence{}, nativeError("staleReference", "Application identity changed during discovery")
		}
		result.State, result.ProcessID, result.ProcessStartToken = "running", app.PID, app.StartToken
	}
	if err := ctx.Err(); err != nil {
		return ApplicationPresence{}, errors.Join(err, nativeError("incompleteObservation", "Application discovery expired"))
	}
	result.ObservedAt = time.Now()
	return result, nil
}
