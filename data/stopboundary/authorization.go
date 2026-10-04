package stopboundary

import (
	"context"
	"errors"
	"github.com/viant/mechanize/data"
)

// Init checks ingress before generated relation producers normalize links.
func (in *StopBoundaryInput) Init(ctx context.Context) error {
	a, err := data.RequireStopBoundaryAuthority(ctx)
	if err != nil {
		return err
	}
	if in.Namespace != a.Namespace || len(in.StopBoundary) != 1 {
		return errors.New("one exact owned stopped-boundary graph required")
	}
	r := in.StopBoundary[0]
	if r == nil || !same(r.Namespace, a.Namespace) || !same(r.Id, a.RunID) || !sameInt(r.Revision, a.RunRevision) || !same(r.Status, "paused") || !same(r.UpdatedAt, a.Now) || r.PlanId != nil || r.CreatedAt != nil || r.EndlySessionId != nil || r.EndlyOperationId != nil || len(r.Events) != 1 {
		return errors.New("stopped-boundary ingress differs from trusted authority")
	}
	return validateEvent(r.Events[0], a)
}
