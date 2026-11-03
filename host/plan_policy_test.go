package host

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

func TestNativePlanDiscoveryAvoidsWebAndReadOnlyControlAdmission(t *testing.T) {
	q := newObservationPolicyFixture(t, false)
	web := newWebControlFixture(t)
	q.h.webControl = web.manager
	probes := 0
	web.manager.options.CapabilityProbe = func(context.Context, auth.Principal) (map[string]bool, error) {
		probes++
		return map[string]bool{"web:semanticPress": true}, nil
	}
	plan, err := script.Compile(`let value=app("com.fixture.app").getById("public").read("value")`)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(plan)
	policy, err := q.h.PlanPolicy(q.f.ctx, q.f.principal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err = (script.Validator{}).CheckPolicy(plan, policy); err != nil {
		t.Fatal(err)
	}
	if probes != 0 || q.f.starts != 0 || q.read.doctors.Load() != 1 || policy.AllowMutation || policy.AllowAllWeb || policy.AllowedSurfaces["https://fixture.test"] {
		t.Fatal("native read borrowed unrelated discovery or control")
	}
	after, _ := json.Marshal(plan)
	if string(before) != string(after) {
		t.Fatal("discovery modified immutable plan")
	}
	if _, err = q.h.Policy(q.f.ctx, q.f.principal); err != nil {
		t.Fatal(err)
	}
	if probes != 1 {
		t.Fatal("fixture did not exercise browser discovery on full policy", probes)
	}
}
func TestNativePlanClassificationKeepsMixedAndUnknownDiscovery(t *testing.T) {
	for _, mode := range []string{"native-read", "native-write", "web-step", "web-ancestor", "web-binding", "web-surface", "web-predicate", "objective", "artifact", "recovery", "profile", "step-profile", "step-checkpoint", "unknown-alias"} {
		t.Run(mode, func(t *testing.T) {
			plan, err := script.Compile(`let value=app("com.fixture.app").getById("public").read("value")`)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "native-write":
				plan.Steps[0].Effect.Class = model.ExternalNonIdempotent
			case "web-step":
				plan.Steps[0].Target.Surface = model.Surface{Kind: "web", Origin: "https://fixture.test"}
			case "web-ancestor":
				plan.Steps[0].Target.Ancestor = &model.Selector{Surface: model.Surface{Kind: "web"}}
			case "step-profile":
				plan.Steps[0].SemanticsProfile = "custom"
			case "step-checkpoint":
				plan.Steps[0].Checkpoint = &model.CheckpointPolicy{}
			case "web-binding":
				plan.Bindings = append(plan.Bindings, model.Binding{Selector: &model.Selector{Surface: model.Surface{Kind: "web"}}})
			case "web-surface":
				plan.Surfaces = map[string]model.Surface{"extra": {Kind: "web"}}
			case "web-predicate":
				plan.Steps[0].Postcondition = &model.Predicate{Kind: "adapter", Adapter: "web"}
			case "objective":
				plan.Objective = &model.Predicate{}
			case "artifact":
				plan.Artifacts = map[string]model.ArtifactDefinition{"file": {}}
			case "recovery":
				plan.Recovery = &model.RecoveryPolicy{}
			case "profile":
				plan.Requires = &model.Requirements{SemanticsProfiles: []string{"custom"}}
			case "unknown-alias":
				plan.Steps[0].Postcondition = &model.Predicate{Kind: "adapter", Adapter: "native", Scope: model.PredicateScope{SurfaceRef: "missing"}}
			}
			native, readOnly := nativePlanOnly(plan)
			if native != (mode == "native-read" || mode == "native-write") || native && readOnly != (mode == "native-read") {
				t.Fatal("incorrect scope classification", native, readOnly)
			}
		})
	}
}
func TestNativeDispatchDiscoveryRetainsExactAdmissionWithoutBrowserProbe(t *testing.T) {
	h, f := hostControlFixture(t)
	a := f.admit(t)
	web := newWebControlFixture(t)
	h.webControl = web.manager
	web.manager.options.CapabilityProbe = func(context.Context, auth.Principal) (map[string]bool, error) {
		t.Fatal("native dispatch probed browser")
		return nil, nil
	}
	before := f.qualifications
	if _, err := h.nativeOnlyPolicy(f.ctx, f.principal, &a, false); err != nil {
		t.Fatal(err)
	}
	if f.qualifications != before {
		t.Fatal("same-operation admission was discarded")
	}
}
