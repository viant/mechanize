package mcp

import (
	"github.com/viant/mechanize/model"
	"strings"
)

// The website may control Mechanize through its canonical APIs, never through
// the human console that can grant authority to that same website.
func controllerSurfaceAllowed(surface model.Surface) bool {
	return !strings.EqualFold(strings.TrimSpace(surface.BundleID), "com.viant.mechanize.consent")
}
func controllerSelectorAllowed(selector *model.Selector) bool {
	for selector != nil {
		if !controllerSurfaceAllowed(selector.Surface) {
			return false
		}
		selector = selector.Ancestor
	}
	return true
}
func controllerPlanAllowed(plan *model.Plan) bool {
	if plan == nil {
		return false
	}
	for _, surface := range plan.Surfaces {
		if !controllerSurfaceAllowed(surface) {
			return false
		}
	}
	predicate := func(p *model.Predicate) bool { return p == nil || controllerSelectorAllowed(p.Scope.Target) }
	if !predicate(plan.Objective) {
		return false
	}
	for _, binding := range plan.Bindings {
		if !controllerSelectorAllowed(binding.Selector) {
			return false
		}
	}
	for _, step := range plan.Steps {
		if !controllerSelectorAllowed(&step.Target) || !predicate(step.Precondition) || !predicate(step.Postcondition) || !predicate(step.Effect.Reconcile) {
			return false
		}
	}
	return true
}
