package script

import (
	"fmt"
	"github.com/viant/mechanize/model"
	"io"
	"strings"
)

// Definition describes the closed surface exposed to language clients.
type Definition struct {
	Action         string                     `json:"action,omitempty"`
	Arguments      []model.ValueKind          `json:"arguments,omitempty"`
	Name           string                     `json:"name"`
	Receivers      []string                   `json:"receivers"`
	Result         string                     `json:"result"`
	Effect         model.EffectClass          `json:"effect"`
	Capabilities   []string                   `json:"capabilities"`
	DefaultOptions map[string]model.Value     `json:"defaultOptions,omitempty"`
	Options        map[string]model.ValueKind `json:"options,omitempty"`
}
type Registry struct{}

func (Registry) Describe() []Definition {
	definitions := []Definition{
		{Name: "app", Arguments: []model.ValueKind{model.StringValue}, Result: "app", Effect: model.ReadOnly, Options: map[string]model.ValueKind{"processId": model.NumberValue, "processStartToken": model.StringValue}},
		{Name: "web.tab", Result: "page", Effect: model.ReadOnly, Options: map[string]model.ValueKind{"origin": model.StringValue, "title": model.StringValue, "id": model.StringValue}},
		{Name: "menuBar", Receivers: []string{"app"}, Result: "app", Effect: model.ReadOnly, Capabilities: []string{"menuBarScope"}},
		{Name: "focusedElement", Receivers: []string{"app"}, Result: "app", Effect: model.ReadOnly, Capabilities: []string{"focusedElementScope"}},
		{Name: "window", Receivers: []string{"app"}, Result: "window", Effect: model.ReadOnly}, {Name: "frame", Receivers: []string{"page"}, Result: "frame", Effect: model.ReadOnly, Capabilities: []string{"frameScope"}},
		{Name: "getByRole", Receivers: []string{"app", "window", "page", "frame", "locator"}, Result: "locator", Effect: model.ReadOnly, Capabilities: []string{"roleLocator"}},
		{Name: "getById", Options: map[string]model.ValueKind{"exact": model.BoolValue}, DefaultOptions: map[string]model.Value{"exact": {Kind: model.BoolValue, Bool: true}}, Receivers: []string{"app", "window", "page", "frame", "locator"}, Result: "locator", Effect: model.ReadOnly, Capabilities: []string{"idLocator"}},
		{Name: "getByName", Receivers: []string{"app", "window", "page", "frame", "locator"}, Result: "locator", Effect: model.ReadOnly, Capabilities: []string{"nameLocator"}},
		{Name: "getByText", Receivers: []string{"app", "window", "page", "frame", "locator"}, Result: "locator", Effect: model.ReadOnly, Capabilities: []string{"textLocator"}},
		{Name: "getByLabel", Receivers: []string{"app", "window", "page", "frame", "locator"}, Result: "locator", Effect: model.ReadOnly, Capabilities: []string{"labelRelationships"}},
		{Name: "getByTestId", Options: map[string]model.ValueKind{"exact": model.BoolValue}, DefaultOptions: map[string]model.Value{"exact": {Kind: model.BoolValue, Bool: true}}, Receivers: []string{"app", "window", "page", "frame", "locator"}, Result: "locator", Effect: model.ReadOnly, Capabilities: []string{"testIdLocator"}},
	}
	for _, a := range model.Actions() {
		effect := model.ExternalNonIdempotent
		result := "void"
		if a.ReadOnly {
			effect = model.ReadOnly
		}
		if a.Method == "read" {
			result = "value"
		}
		args := []model.ValueKind{}
		if a.Argument != "" {
			args = append(args, a.ArgumentType)
		}
		receivers := []string{"locator"}
		if a.Method == "open" || a.Method == "activate" || a.Method == "pressWindowKey" || a.Method == "clickWindowFrame" {
			receivers = []string{"app"}
		}
		if a.Method == "expect" {
			receivers = []string{"app", "window", "page", "frame", "locator"}
		}
		if a.Method == "pressWindowKey" {
			definitions = append(definitions, Definition{Action: a.Action, Name: a.Method, Receivers: receivers, Result: result, Effect: effect, Capabilities: []string{a.Capability}, Options: map[string]model.ValueKind{"windowId": model.NumberValue, "key": model.StringValue, "timeout": model.DurationValue}})
			continue
		}
		if a.Method == "clickWindowFrame" {
			definitions = append(definitions, Definition{Action: a.Action, Name: a.Method, Receivers: receivers, Result: result, Effect: effect, Capabilities: []string{a.Capability}, Options: map[string]model.ValueKind{"captureRef": model.StringValue, "x": model.NumberValue, "y": model.NumberValue, "timeout": model.DurationValue}})
			continue
		}
		definitions = append(definitions, Definition{Action: a.Action, Arguments: args, Name: a.Method, Receivers: receivers, Result: result, Effect: effect, Capabilities: []string{a.Capability}, Options: map[string]model.ValueKind{"timeout": model.DurationValue}})
	}
	for _, n := range []string{"within", "all", "nth"} {
		definitions = append(definitions, Definition{Name: n, Receivers: []string{"locator"}, Result: "locator", Effect: model.ReadOnly})
	}
	return definitions
}

// CheckCapabilities checks explicit backend qualifications without fallback reinterpretation.
func (Registry) CheckCapabilities(plan *model.Plan, supported map[string]bool) error {
	for _, s := range plan.Steps {
		definition, ok := model.ActionByName(s.Action)
		if !ok {
			return fmt.Errorf("unsupported action %s", s.Action)
		}
		need := definition.Capability
		if !supported[s.Target.Surface.Kind+":"+need] {
			return fmt.Errorf("step %s requires capability %s:%s", s.ID, s.Target.Surface.Kind, need)
		}
		if s.Assertion != nil && s.Assertion.Matcher == "toBeChecked" && !supported[s.Target.Surface.Kind+":checkedObservation"] {
			return fmt.Errorf("step %s requires checkedObservation capability", s.ID)
		}
		for target := &s.Target; target != nil; target = target.Ancestor {
			if target.Scope.NativeRoot != "" {
				capability := map[string]string{"menuBar": "menuBarScope", "focusedElement": "focusedElementScope"}[target.Scope.NativeRoot]
				if capability == "" || !supported[s.Target.Surface.Kind+":"+capability] {
					return fmt.Errorf("step %s requires native root capability", s.ID)
				}
			}
			if target.Ancestor != nil && !supported[s.Target.Surface.Kind+":ancestorScope"] {
				return fmt.Errorf("step %s requires ancestorScope capability", s.ID)
			}
			if target.Cardinality != "one" && !supported[s.Target.Surface.Kind+":orderedQuery"] {
				return fmt.Errorf("step %s requires orderedQuery capability", s.ID)
			}
			if len(target.Scope.Frame) != 0 && !supported[s.Target.Surface.Kind+":frameScope"] {
				return fmt.Errorf("step %s requires frameScope capability", s.ID)
			}
			if len(target.Scope.Window) != 0 && !supported[s.Target.Surface.Kind+":windowScope"] {
				return fmt.Errorf("step %s requires windowScope capability", s.ID)
			}
			if target.Locator == nil {
				continue
			}
			strategy := map[string]string{"role": "roleLocator", "id": "idLocator", "name": "nameLocator", "text": "textLocator", "label": "labelRelationships", "testId": "testIdLocator"}[target.Locator.Strategy]
			if !supported[s.Target.Surface.Kind+":"+strategy] {
				return fmt.Errorf("step %s requires capability %s:%s", s.ID, s.Target.Surface.Kind, strategy)
			}
		}
	}
	return nil
}

// DecodePlan is the strict JSON frontend for the identical typed IR. No independent scheduler is created.
func DecodePlan(r io.Reader) (*model.Plan, error) { return DecodeJSON(r) }

type Policy struct {
	// Operator-selected broad scope; workflow constraints still narrow targets.
	AllowAllNative    bool
	AllowAllWeb       bool
	AllowedSurfaces   map[string]bool
	AllowMutation     bool
	Capabilities      map[string]bool
	CapabilityReasons map[string]string
}

func (p Policy) permits(surface model.Surface, key string) bool {
	return p.AllowedSurfaces[key] || surface.Kind == "native" && p.AllowAllNative || surface.Kind == "web" && p.AllowAllWeb
}

type Validator struct{}

// CheckStepPolicy rechecks current execution authority for a step whose full
// immutable workflow was already validated. Adapter/input/binding declarations
// belong to that workflow; inventing a one-step workflow loses those contracts.
func (Validator) CheckStepPolicy(step model.Step, p Policy) error {
	if err := step.Validate(); err != nil {
		return err
	}
	key := step.Target.Surface.BundleID
	if step.Target.Surface.Kind == "web" {
		key = step.Target.Surface.Origin
		if key == "" {
			key = "tab:" + step.Target.Surface.TabID
		}
	}
	if !p.permits(step.Target.Surface, key) {
		return fmt.Errorf("step %s surface is outside allowed scope", step.ID)
	}
	if step.Effect.Class != model.ReadOnly && !p.AllowMutation {
		return fmt.Errorf("step %s mutation is not allowed", step.ID)
	}
	return (Registry{}).CheckCapabilities(&model.Plan{Steps: []model.Step{step}}, p.Capabilities)
}

func (Validator) CheckPolicy(plan *model.Plan, p Policy) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	for _, surface := range plan.Surfaces {
		key := surface.BundleID
		if surface.Kind == "web" {
			key = surface.Origin
			if key == "" {
				key = "tab:" + surface.TabID
			}
		}
		if !p.permits(surface, key) {
			return fmt.Errorf("declared surface outside allowed scope")
		}
	}
	for _, s := range plan.Steps {
		if c := plan.Constraints; c != nil {
			if s.Target.Surface.Kind == "native" && len(c.AllowedApps) > 0 && !stringContains(c.AllowedApps, s.Target.Surface.BundleID) {
				return fmt.Errorf("step %s violates app constraints", s.ID)
			}
			if s.Target.Surface.Kind == "web" && len(c.AllowedOrigins) > 0 && !stringContains(c.AllowedOrigins, s.Target.Surface.Origin) {
				return fmt.Errorf("step %s violates origin constraints", s.ID)
			}
		}
		key := s.Target.Surface.BundleID
		if s.Target.Surface.Kind == "web" {
			key = s.Target.Surface.Origin
			if key == "" {
				key = "tab:" + s.Target.Surface.TabID
			}
		}
		if !p.permits(s.Target.Surface, key) {
			return fmt.Errorf("step %s surface is outside allowed scope", s.ID)
		}
		if s.Effect.Class != model.ReadOnly && !p.AllowMutation {
			return fmt.Errorf("step %s mutation is not allowed", s.ID)
		}
	}
	return (Registry{}).CheckCapabilities(plan, p.Capabilities)
}

type Explainer struct{}

func (Explainer) Explain(p *model.Plan) string {
	var b strings.Builder
	if p.Goal != nil {
		fmt.Fprintf(&b, "Declared goal (descriptive, not proof of completion): %s\n", p.Goal.Description)
		for _, criterion := range p.Goal.SuccessCriteria {
			fmt.Fprintf(&b, "Success criterion: %s\n", criterion)
		}
	}
	for _, s := range p.Steps {
		fmt.Fprintf(&b, "%s: %s on %s (%s, strict one, %dms)\n", s.ID, s.Action, s.Target.Surface.Kind, s.Effect.Class, s.TimeoutMs)
		if s.Purpose != "" {
			fmt.Fprintf(&b, "Purpose: %s\n", s.Purpose)
		}
	}
	return b.String()
}

func stringContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
