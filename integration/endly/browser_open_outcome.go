package endly

import (
	"context"
	"errors"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

// OriginOpeningOutcome contains only closed dispatch metadata from the normal
// executor callback, including failures before a durable attempt was admitted.
// It carries no page content, error text, values, or permission to replay.
type OriginOpeningOutcome struct {
	DispatchState string
	Reason        string
}

func originOpeningOutcome(result StepResult, err error) OriginOpeningOutcome {
	out := OriginOpeningOutcome{DispatchState: result.DispatchState, Reason: "none"}
	var diagnostic *model.MechanizeError
	if errors.As(err, &diagnostic) {
		out.Reason = model.OpenOriginReason(diagnostic.Code)
		if out.DispatchState == "" {
			out.DispatchState = diagnostic.DispatchState
		}
	} else if err != nil {
		out.Reason = "openOriginUnavailable"
	}
	if err != nil && out.Reason == "none" {
		out.Reason = "openOriginUnavailable"
	}
	if out.DispatchState != "dispatched" && out.DispatchState != "notDispatched" {
		out.DispatchState = "unknown"
	}
	if out.DispatchState == "unknown" && out.Reason == "none" {
		out.Reason = "openOriginUnknown"
	}
	if out.DispatchState == "notDispatched" && out.Reason == "none" {
		out.Reason = "openOriginRejected"
	}
	return out
}
func (r *Runtime) OriginOpeningOutcome(ctx context.Context, session, operation string) (OriginOpeningOutcome, error) {
	actor, e := auth.FromContext(ctx)
	if e != nil {
		return OriginOpeningOutcome{}, e
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	owner, ok := r.principals[session]
	if !ok || owner.Namespace != actor.Namespace || owner.ClientID != actor.ClientID {
		return OriginOpeningOutcome{}, auth.ErrUnauthorized
	}
	for _, p := range r.programs {
		if p.owner == session && p.operationID == operation && len(p.plan.Steps) == 1 && p.plan.Steps[0].Action == "browser.openOrigin" {
			if p.originOpeningOutcome == nil {
				return OriginOpeningOutcome{DispatchState: "unknown", Reason: "openOriginPending"}, nil
			}
			return *p.originOpeningOutcome, nil
		}
	}
	return OriginOpeningOutcome{}, errors.New("owned origin-opening operation unavailable")
}
