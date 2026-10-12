package endly

import (
	"context"
	"errors"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

// TabActivationOutcome contains only closed dispatch metadata from the normal
// executor callback, including failures before a durable attempt was admitted.
// It carries no page content, error text, values, or permission to replay.
type TabActivationOutcome struct {
	DispatchState string
	Reason        string
}

func tabActivationOutcome(result StepResult, err error) TabActivationOutcome {
	out := TabActivationOutcome{DispatchState: result.DispatchState, Reason: "none"}
	var diagnostic *model.MechanizeError
	if errors.As(err, &diagnostic) {
		out.Reason = model.TabActivationReason(diagnostic.Code)
		if out.DispatchState == "" {
			out.DispatchState = diagnostic.DispatchState
		}
	} else if err != nil {
		out.Reason = "tabActivationUnavailable"
	}
	if err != nil && out.Reason == "none" {
		out.Reason = "tabActivationUnavailable"
	}
	if out.DispatchState != "dispatched" && out.DispatchState != "notDispatched" {
		out.DispatchState = "unknown"
	}
	if out.DispatchState == "unknown" && out.Reason == "none" {
		out.Reason = "tabActivationUnknown"
	}
	if out.DispatchState == "notDispatched" && out.Reason == "none" {
		out.Reason = "tabActivationRejected"
	}
	return out
}
func (r *Runtime) TabActivationOutcome(ctx context.Context, session, operation string) (TabActivationOutcome, error) {
	actor, e := auth.FromContext(ctx)
	if e != nil {
		return TabActivationOutcome{}, e
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	owner, ok := r.principals[session]
	if !ok || owner.Namespace != actor.Namespace || owner.ClientID != actor.ClientID {
		return TabActivationOutcome{}, auth.ErrUnauthorized
	}
	for _, p := range r.programs {
		if p.owner == session && p.operationID == operation && len(p.plan.Steps) == 1 && p.plan.Steps[0].Action == "browser.activateTab" {
			if p.tabActivationOutcome == nil {
				return TabActivationOutcome{DispatchState: "unknown", Reason: "tabActivationPending"}, nil
			}
			return *p.tabActivationOutcome, nil
		}
	}
	return TabActivationOutcome{}, errors.New("owned tab-activation operation unavailable")
}
