package host

import (
	"context"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

type policyDiscoveryKey struct{}
type policyDiscovery struct{ nativeOnly, readOnly bool }

func policyDiscoveryFromContext(ctx context.Context) policyDiscovery {
	v, _ := ctx.Value(policyDiscoveryKey{}).(policyDiscovery)
	return v
}

// This context is local to capability discovery. It carries no input authority,
// cached trust, consent or process proof and is not returned to the dispatcher.
func (h *Host) nativeOnlyPolicy(ctx context.Context, p auth.Principal, a *NativeControlAdmission, readOnly bool) (script.Policy, error) {
	return h.policy(context.WithValue(ctx, policyDiscoveryKey{}, policyDiscovery{nativeOnly: true, readOnly: readOnly}), p, a)
}
func nativeSelectorOnly(s *model.Selector) bool {
	for depth := 0; s != nil; s = s.Ancestor {
		if depth >= 32 || s.Surface.Kind != "native" {
			return false
		}
		depth++
	}
	return true
}
func nativePredicateOnly(p *model.Predicate, surfaces map[string]model.Surface) bool {
	if p == nil {
		return true
	}
	if p.Kind != "adapter" || p.Adapter != "native" {
		return false
	}
	if p.Scope.Target != nil {
		return nativeSelectorOnly(p.Scope.Target)
	}
	surface, ok := surfaces[p.Scope.SurfaceRef]
	return ok && surface.Kind == "native"
}
func nativeStepOnly(step model.Step, surfaces map[string]model.Surface) bool {
	if step.SemanticsProfile != "" || step.Checkpoint != nil {
		return false
	}
	return nativeSelectorOnly(&step.Target) && nativePredicateOnly(step.Precondition, surfaces) && nativePredicateOnly(step.Postcondition, surfaces) && nativePredicateOnly(step.Effect.Reconcile, surfaces)
}
func nativePlanOnly(p *model.Plan) (bool, bool) {
	if p == nil || len(p.Steps) == 0 || p.Objective != nil || p.Recovery != nil || len(p.Artifacts) > 0 || len(p.Checkpoints) > 0 {
		return false, false
	}
	if p.Constraints != nil && len(p.Constraints.AllowedOrigins) > 0 {
		return false, false
	}
	if p.Requires != nil {
		if len(p.Requires.SemanticsProfiles) > 0 {
			return false, false
		}
		for _, a := range p.Requires.Adapters {
			if a != "native" {
				return false, false
			}
		}
	}
	for _, s := range p.Surfaces {
		if s.Kind != "native" {
			return false, false
		}
	}
	for _, b := range p.Bindings {
		if b.Selector != nil && !nativeSelectorOnly(b.Selector) {
			return false, false
		}
	}
	readOnly := true
	for _, step := range p.Steps {
		if !nativeStepOnly(step, p.Surfaces) {
			return false, false
		}
		if step.Effect.Class != model.ReadOnly {
			readOnly = false
		}
	}
	return true, readOnly
}

// PlanPolicy narrows only fully understood native plans. Mixed/unknown plans keep
// the existing complete policy. The MCP layer still validates every plan against
// this policy, and the executor independently authorizes each actual operation.
func (h *Host) PlanPolicy(ctx context.Context, p auth.Principal, plan *model.Plan) (script.Policy, error) {
	if native, readOnly := nativePlanOnly(plan); native {
		return h.nativeOnlyPolicy(ctx, p, nil, readOnly)
	}
	return h.Policy(ctx, p)
}
