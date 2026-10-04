package recovery

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/viant/mechanize/model"
)

func locatorContractFixture(t *testing.T) (context.Context, RecoveryContext, PlanPatch) {
	t.Helper()
	ctx, r, patch := fixture()
	surface := r.Base.Steps[0].Target.Surface
	surface.ProcessID, surface.ProcessStartToken = 123, "1790000000:0"
	window := map[string]model.Value{"title": {Kind: model.StringValue, String: "Invoice"}, "role": {Kind: model.StringValue, String: "AXWindow"}}
	target := model.Selector{Surface: surface, Scope: model.Scope{Window: window}, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "old-submit"}, Exact: true}, Ancestor: &model.Selector{Surface: surface, Scope: model.Scope{Window: window}, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "invoice-panel"}, Exact: true}}}
	r.Base.Surfaces["app"] = surface
	r.Base.Steps[0].Target = target
	r.Contracts[0].Surface = surface
	r.Contracts[0].TargetScope = &target
	r.ObjectiveHash = ObjectiveHash(r.Base)
	patch.ObjectiveHash, patch.BaseHash = r.ObjectiveHash, Hash(r.Base)
	patch.RemainingSteps = []model.Step{r.Base.Steps[0]}
	// The trusted scope, base and caller proposal must not share mutable maps or
	// pointers: each mutation below models an independent incoming proposal.
	copyValue := func(in, out any) {
		body, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(body, out); err != nil {
			t.Fatal(err)
		}
	}
	var detached RecoveryContext
	copyValue(r, &detached)
	var detachedPatch PlanPatch
	copyValue(patch, &detachedPatch)
	return ctx, detached, detachedPatch
}

func TestLocatorContractAllowsOnlyExactSemanticLeafChange(t *testing.T) {
	for _, strategy := range []string{"id", "name", "role"} {
		t.Run(strategy, func(t *testing.T) {
			ctx, r, patch := locatorContractFixture(t)
			locator := &model.Locator{Strategy: strategy, Value: model.Value{Kind: model.StringValue, String: "new-submit"}, Exact: true}
			if strategy == "role" {
				locator.Value.String = "button"
				locator.Name = &model.Value{Kind: model.StringValue, String: "Save invoice"}
			}
			patch.RemainingSteps[0].Target.Locator = locator
			before := Hash(r)
			revision, err := Validate(ctx, r, patch)
			if err != nil {
				t.Fatal(err)
			}
			if Hash(r) != before || !reflect.DeepEqual(revision.Plan.Steps[0].Target.Locator, locator) || revision.ObjectiveHash != r.ObjectiveHash || !reflect.DeepEqual(revision.Plan.Steps[0].Effect, r.Base.Steps[0].Effect) || !reflect.DeepEqual(revision.Plan.Steps[0].Postcondition, r.Base.Steps[0].Postcondition) {
				t.Fatal("leaf repair changed trusted context, objective or outcome contract")
			}
		})
	}
}

func TestLocatorContractRejectsScopeChanges(t *testing.T) {
	mutations := map[string]func(*model.Selector){
		"erase_window": func(s *model.Selector) { s.Scope.Window = nil },
		"change_window": func(s *model.Selector) {
			s.Scope.Window["title"] = model.Value{Kind: model.StringValue, String: "Other invoice"}
		},
		"add_window_filter": func(s *model.Selector) {
			s.Scope.Window["documentKey"] = model.Value{Kind: model.StringValue, String: "other-document"}
		},
		"erase_ancestor":          func(s *model.Selector) { s.Ancestor = nil },
		"change_ancestor_locator": func(s *model.Selector) { s.Ancestor.Locator.Value.String = "other-panel" },
		"change_ancestor_window": func(s *model.Selector) {
			s.Ancestor.Scope.Window["title"] = model.Value{Kind: model.StringValue, String: "Other invoice"}
		},
		"change_process":       func(s *model.Selector) { s.Surface.ProcessID++; s.Ancestor.Surface = s.Surface },
		"change_process_birth": func(s *model.Selector) { s.Surface.ProcessStartToken = "1790000001:0"; s.Ancestor.Surface = s.Surface },
		"erase_process": func(s *model.Selector) {
			s.Surface.ProcessID = 0
			s.Surface.ProcessStartToken = ""
			s.Ancestor.Surface = s.Surface
		},
		"change_order":       func(s *model.Selector) { s.Order = "tree" },
		"change_cardinality": func(s *model.Selector) { index := 0; s.Cardinality, s.Order, s.Index = "nth", "tree", &index },
		"erase_locator":      func(s *model.Selector) { s.Locator = nil },
		"inexact_locator":    func(s *model.Selector) { s.Locator.Exact = false },
		"reference_locator": func(s *model.Selector) {
			s.Locator.Value = model.Value{Kind: model.ReferenceValue, Ref: "input.selector"}
		},
		"reference_role_name": func(s *model.Selector) {
			s.Locator.Strategy = "role"
			s.Locator.Value.String = "button"
			s.Locator.Name = &model.Value{Kind: model.ReferenceValue, Ref: "input.selector"}
		},
		"text_locator":  func(s *model.Selector) { s.Locator.Strategy = "text" },
		"empty_locator": func(s *model.Selector) { s.Locator.Value.String = "" },
		"frame_on_native": func(s *model.Selector) {
			s.Scope.Frame = map[string]model.Value{"id": {Kind: model.StringValue, String: "other-frame"}}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			ctx, r, patch := locatorContractFixture(t)
			mutate(&patch.RemainingSteps[0].Target)
			// Keep contract surface matching so process changes cannot rely only
			// on existing profile/surface lookup to reject a broadened target.
			r.Contracts[0].Surface = patch.RemainingSteps[0].Target.Surface
			if _, err := Validate(ctx, r, patch); err == nil {
				t.Fatal("scope change accepted by locator-only contract")
			}
		})
	}
}

func TestLocatorContractRejectsInvalidTrustedScope(t *testing.T) {
	for _, name := range []string{"missing_locator", "reference_locator", "inexact_locator", "invalid_cardinality", "unsupported_strategy"} {
		t.Run(name, func(t *testing.T) {
			ctx, r, patch := locatorContractFixture(t)
			scope := r.Contracts[0].TargetScope
			switch name {
			case "missing_locator":
				scope.Locator = nil
			case "reference_locator":
				scope.Locator.Value = model.Value{Kind: model.ReferenceValue, Ref: "input.selector"}
			case "inexact_locator":
				scope.Locator.Exact = false
			case "invalid_cardinality":
				scope.Cardinality = "unbounded"
			case "unsupported_strategy":
				scope.Locator.Strategy = "text"
			}
			if _, err := Validate(ctx, r, patch); err == nil {
				t.Fatal("invalid trusted locator contract accepted")
			}
		})
	}
}

func TestNilLocatorContractPreservesFullRouteQualification(t *testing.T) {
	ctx, r, patch := locatorContractFixture(t)
	r.Contracts[0].TargetScope = nil
	patch.RemainingSteps[0].Target.Scope.Window = nil
	patch.RemainingSteps[0].Target.Ancestor = nil
	if _, err := Validate(ctx, r, patch); err != nil {
		t.Fatalf("existing full-route qualification changed: %v", err)
	}
}

func TestLocatorContractPreservesWebFrameBoundary(t *testing.T) {
	for _, mutation := range []string{"leaf", "erase_frame", "change_frame", "change_ancestor_frame", "change_tab"} {
		t.Run(mutation, func(t *testing.T) {
			ctx, r, patch := locatorContractFixture(t)
			surface := model.Surface{Kind: "web", Origin: "https://fixture.example", TabID: "owned-tab"}
			target := patch.RemainingSteps[0].Target
			target.Surface, target.Ancestor.Surface = surface, surface
			target.Scope = model.Scope{Frame: map[string]model.Value{"id": {Kind: model.StringValue, String: "payment-frame"}}}
			target.Ancestor.Scope = target.Scope
			r.Base.Surfaces["app"] = surface
			r.Base.Constraints.AllowedApps = nil
			r.Base.Constraints.AllowedOrigins = []string{surface.Origin}
			r.Base.Steps[0].Target = target
			r.Contracts[0].Surface = surface
			r.Contracts[0].TargetScope = &target
			r.ObjectiveHash = ObjectiveHash(r.Base)
			patch.ObjectiveHash, patch.BaseHash = r.ObjectiveHash, Hash(r.Base)
			// Detach the proposal from its enrolled target before editing it.
			body, err := json.Marshal(target)
			if err != nil {
				t.Fatal(err)
			}
			var detached model.Selector
			if err = json.Unmarshal(body, &detached); err != nil {
				t.Fatal(err)
			}
			patch.RemainingSteps[0].Target = detached
			proposed := &patch.RemainingSteps[0].Target
			proposed.Locator.Value.String = "new-submit"
			switch mutation {
			case "erase_frame":
				proposed.Scope.Frame = nil
			case "change_frame":
				proposed.Scope.Frame["id"] = model.Value{Kind: model.StringValue, String: "other-frame"}
			case "change_ancestor_frame":
				proposed.Ancestor.Scope.Frame = nil
			case "change_tab":
				proposed.Surface.TabID = "other-tab"
				proposed.Ancestor.Surface = proposed.Surface
				r.Contracts[0].Surface = proposed.Surface
			}
			_, err = Validate(ctx, r, patch)
			if mutation == "leaf" && err != nil {
				t.Fatalf("web leaf repair rejected: %v", err)
			}
			if mutation != "leaf" && err == nil {
				t.Fatal("web frame/tab boundary changed")
			}
		})
	}
}
