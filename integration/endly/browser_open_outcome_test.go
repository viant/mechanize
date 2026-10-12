package endly

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestOriginOpeningOutcomeClosedPendingAndRefusal(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	entry := &program{owner: "session", operationID: "operation", plan: model.Plan{Steps: []model.Step{{Action: "browser.openOrigin"}}}}
	r := &Runtime{principals: map[string]auth.Principal{"session": p}, programs: map[string]*program{"run": entry}}
	pending, e := r.OriginOpeningOutcome(ctx, "session", "operation")
	if e != nil || pending.DispatchState != "unknown" || pending.Reason != "openOriginPending" {
		t.Fatal("pending metadata claimed creation/refusal", pending, e)
	}
	for _, tc := range []struct {
		result        StepResult
		err           error
		state, reason string
	}{
		{StepResult{}, &model.MechanizeError{Code: "unsupportedWorker", Message: "PRIVATE_CANARY", DispatchState: "notDispatched"}, "notDispatched", "unsupportedWorker"},
		{StepResult{DispatchState: "unknown"}, errors.New("PRIVATE_CANARY"), "unknown", "openOriginUnavailable"},
		{StepResult{}, &model.MechanizeError{Code: "PRIVATE_CANARY", DispatchState: "notDispatched"}, "notDispatched", "openOriginUnavailable"},
	} {
		out := originOpeningOutcome(tc.result, tc.err)
		if out.DispatchState != tc.state || out.Reason != tc.reason {
			t.Fatal("closed metadata changed", out)
		}
	}
	foreign := p
	foreign.ClientID = "foreign"
	if _, e = r.OriginOpeningOutcome(auth.WithPrincipal(context.Background(), foreign), "session", "operation"); e == nil {
		t.Fatal("foreign actor read opening status")
	}
}
