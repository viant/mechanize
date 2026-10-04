package durable

import (
	"context"
	"errors"
	"reflect"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/standalone"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/loadrun"
	repairs "github.com/viant/mechanize/engine/recovery"
	"github.com/viant/mechanize/model"
)

func hasAncestorAttempts(run *loadrun.Run, planID string) bool {
	for _, attempt := range run.Attempts {
		if attempt.PlanId != nil && *attempt.PlanId != planID {
			return true
		}
	}
	return false
}

// repairSnapshotLocked is invoked with the principal's user.mu already held.
// Direct invocation of the SAME scoped standalone server avoids lock reentry;
// every database read remains the generated LoadRecovery use-case component.
func repairSnapshotLocked(ctx context.Context, server *standalone.Server, p auth.Principal, runID, planID string, plan model.Plan, inputs map[string]model.Value) (repairs.Snapshot, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return repairs.Snapshot{}, auth.ErrUnauthorized
	}
	if _, err = data.RequireScope(ctx, p.Namespace); err != nil {
		return repairs.Snapshot{}, err
	}
	service, err := repairs.New(repairs.Options{Invoke: func(ctx context.Context, principal auth.Principal, request exec.ComponentRequest) (any, error) {
		actor, err := auth.FromContext(ctx)
		if err != nil || actor.Namespace != p.Namespace || principal.Namespace != p.Namespace || actor.ClientID != p.ClientID {
			return nil, auth.ErrUnauthorized
		}
		return server.InvokeComponent(ctx, request)
	}, Authorize: func(ctx context.Context, principal auth.Principal, _ model.Surface) error {
		actor, err := auth.FromContext(ctx)
		if err != nil || actor.Namespace != p.Namespace || principal.Namespace != p.Namespace || actor.ClientID != p.ClientID {
			return auth.ErrUnauthorized
		}
		_, err = data.RequireScope(ctx, p.Namespace)
		return err
	}})
	if err != nil {
		return repairs.Snapshot{}, err
	}
	snapshot, err := service.Snapshot(ctx, actual, runID)
	if err != nil {
		return repairs.Snapshot{}, err
	}
	if snapshot.Unknown || snapshot.Reference.RunID != runID || snapshot.Reference.PlanID != planID || snapshot.Repair == nil || snapshot.Repair.NewPlanID != planID || snapshot.Repair.RunID != runID || !reflect.DeepEqual(snapshot.Plan, plan) || !reflect.DeepEqual(snapshot.Inputs, inputs) {
		return repairs.Snapshot{}, errors.New("admitted immutable repair lineage does not match the active run")
	}
	return snapshot, nil
}
