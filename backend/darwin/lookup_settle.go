package darwin

import (
	"context"
	"errors"
	"time"

	"github.com/viant/mechanize/model"
)

// Only fresh read preparation may settle. This runs under the gateway lock,
// before lease installation or input dispatch, and never changes the selector.
// Unbound process selectors and ordinary reads retain one-shot behavior.
func (g *Gateway) lookupForStep(ctx context.Context, step model.Step, values map[string]model.Value, windowScope map[string]string, mutation bool) (model.Observation, model.Node, error) {
	settle := mutation && step.Target.Surface.ProcessID > 0 && step.Target.Surface.ProcessStartToken != ""
	until := time.Now().Add(time.Second)
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return model.Observation{}, model.Node{}, err
		}
		observation, err := g.observeWindowSnapshot(ctx, step.Target.Surface, step.Target.Scope.NativeRoot, step.Action == "window.moveTo", windowScope, step.Target.Scope.NativeMenu)
		var node model.Node
		if err == nil {
			node, err = resolve(observation, step.Target, values)
		}
		if canceled := ctx.Err(); canceled != nil {
			return observation, model.Node{}, canceled
		}
		if err == nil || !settle || attempt >= 2 || !time.Now().Before(until) || !transientLookupRead(err) {
			return observation, node, err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return observation, model.Node{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func transientLookupRead(err error) bool {
	var transport *TransportError
	if errors.As(err, &transport) {
		return false
	}
	code, stage, dispatch := "", "", ""
	var local *model.MechanizeError
	var helper *NativeError
	if errors.As(err, &local) {
		code, stage, dispatch = local.Code, local.Stage, local.DispatchState
	} else if errors.As(err, &helper) {
		code, stage, dispatch = helper.Code, helper.Stage, helper.DispatchState
	}
	if stage != "native" || dispatch != "notDispatched" {
		return false
	}
	switch code {
	case "incompleteObservation", "rootUnavailable", "targetNotFound":
		return true
	}
	return false
}
