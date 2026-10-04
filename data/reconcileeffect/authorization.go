package reconcileeffect

import (
	"context"
	"errors"
	"github.com/viant/mechanize/data"
)

// Init rejects forged ingress before generated relation producers normalize links.
func (in *ReconcileEffectInput) Init(ctx context.Context) error {
	a, err := data.RequireReconcileEffectAuthority(ctx)
	if err != nil {
		return err
	}
	if in.Namespace != a.Namespace || len(in.ReconcileEffect) != 1 {
		return errors.New("one exact owned reconciliation graph required")
	}
	r := in.ReconcileEffect[0]
	if r == nil || !same(r.Namespace, a.Namespace) || !same(r.Id, a.RunID) || !sameInt(r.Revision, a.RunRevision) || !same(r.Status, "paused") || !same(r.UpdatedAt, a.Now) || r.PlanId != nil || r.CreatedAt != nil || r.EndlySessionId != nil || r.EndlyOperationId != nil || len(r.Plans) != 0 || len(r.Attempts) != 0 || len(r.Effects) != 1 || len(r.Events) != 1 {
		return errors.New("reconciliation run ingress differs from trusted authority")
	}
	e := r.Effects[0]
	if e == nil || !same(e.Namespace, a.Namespace) || !same(e.Id, a.EffectID) || !same(e.RunId, a.RunID) || !same(e.AttemptId, a.AttemptID) || !sameInt(e.Revision, a.EffectRevision) || !same(e.State, "confirmed") || !same(e.EvidenceJson, a.EvidenceJSON) || (e.BusinessKey != nil && !same(e.BusinessKey, a.BusinessKey)) || len(e.Milestones) != 1 {
		return errors.New("reconciliation effect ingress differs from trusted authority")
	}
	if err := validateMilestone(e.Milestones[0], a); err != nil {
		return err
	}
	return validateEvent(r.Events[0], a)
}
