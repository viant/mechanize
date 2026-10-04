package model

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func (p Predicate) Validate() error {
	if p.TimeoutMs < 1 || p.TimeoutMs > 3600000 || p.FreshnessMs < 1 || p.FreshnessMs > p.TimeoutMs {
		return fmt.Errorf("predicate needs bounded timeout and freshness")
	}
	if p.RequiredAuthority != "observational" && p.RequiredAuthority != "authoritative" {
		return fmt.Errorf("invalid predicate authority")
	}
	if (p.Scope.SurfaceRef == "") == (p.Scope.Target == nil) {
		return fmt.Errorf("predicate needs exactly one scope")
	}
	if p.Scope.Target != nil {
		if err := p.Scope.Target.Validate(); err != nil {
			return err
		}
	}
	switch p.Kind {
	case "adapter":
		if p.Adapter == "" || p.Name == "" || p.Matcher != nil {
			return fmt.Errorf("adapter predicate needs adapter/name")
		}
	case "element":
		if p.Scope.Target == nil || p.Adapter != "" || p.Name != "" {
			return fmt.Errorf("element predicate needs target")
		}
		if err := validateAssertion(p.Matcher, p.Scope.Target.Locator != nil); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported predicate kind")
	}
	if p.Kind == "adapter" && p.Adapter == "native" && p.Name == "valueEquals" {
		pid, hasPID := p.Inputs["processId"]
		token, hasToken := p.Inputs["processStartToken"]
		if hasPID != hasToken {
			return fmt.Errorf("native.valueEquals requires paired processId and processStartToken")
		}
		if hasPID {
			if pid.Kind == ReferenceValue {
				if pid.Expected != "" && pid.Expected != NumberValue {
					return fmt.Errorf("native process PID reference requires number")
				}
			} else if pid.Kind != NumberValue || pid.Number <= 0 || pid.Number > 2147483647 {
				return fmt.Errorf("native process PID requires a positive bounded number")
			}
			if token.Kind == ReferenceValue {
				if token.Expected != "" && token.Expected != StringValue {
					return fmt.Errorf("native process start token reference requires string")
				}
			} else if token.Kind != StringValue || !ValidProcessStartToken(token.String) {
				return fmt.Errorf("native process start token requires canonical seconds:microseconds")
			}
		}
	}
	for _, v := range p.Inputs {
		if err := v.Validate(); err != nil {
			return err
		}
	}
	return nil
}
func (c CheckpointPolicy) Validate() error {
	if c.Name == "" || len(c.Levels) == 0 {
		return fmt.Errorf("checkpoint needs name and levels")
	}
	seen := map[string]bool{}
	for _, l := range c.Levels {
		if seen[l] {
			return fmt.Errorf("duplicate checkpoint level")
		}
		seen[l] = true
		switch l {
		case "evidence", "runner", "workspace":
		default:
			return fmt.Errorf("unsupported checkpoint level")
		}
	}
	return nil
}
func (p Plan) validateMetadata() error {
	if p.Goal != nil {
		g := p.Goal
		if !utf8.ValidString(g.Description) || len(g.Description) == 0 || len(g.Description) > 4000 || strings.TrimSpace(g.Description) == "" {
			return fmt.Errorf("goal description must be nonempty valid UTF-8 and at most 4000 bytes")
		}
		if len(g.SuccessCriteria) > 16 {
			return fmt.Errorf("goal has more than 16 success criteria")
		}
		for _, criterion := range g.SuccessCriteria {
			if !utf8.ValidString(criterion) || len(criterion) == 0 || len(criterion) > 1000 || strings.TrimSpace(criterion) == "" {
				return fmt.Errorf("goal success criteria must be nonempty valid UTF-8 and at most 1000 bytes")
			}
		}
	}
	for n, i := range p.Inputs {
		if !identifier(n) || !validValueKind(i.Type) {
			return fmt.Errorf("invalid input %s", n)
		}
		if i.Default != nil {
			if i.Default.Kind != i.Type {
				return fmt.Errorf("input default type mismatch")
			}
			if err := i.Default.Validate(); err != nil {
				return err
			}
		}
	}
	for n, s := range p.Surfaces {
		if !identifier(n) {
			return fmt.Errorf("empty surface alias")
		}
		if err := (Selector{Surface: s, Cardinality: "one"}).Validate(); err != nil {
			return err
		}
	}
	for n, a := range p.Artifacts {
		if !identifier(n) || a.FromPath.Kind != StringValue && a.FromPath.Kind != ReferenceValue {
			return fmt.Errorf("invalid artifact")
		}
		if err := a.FromPath.Validate(); err != nil {
			return err
		}
		for _, r := range a.Require {
			if r != "readable" && r != "sha256" {
				return fmt.Errorf("unsupported artifact requirement")
			}
		}
	}
	if p.Recovery != nil {
		r := p.Recovery
		if r.MaxRepairs < 0 || r.MaxRepairs > 10 || r.MaxElapsedMs < 1 || r.MaxElapsedMs > 3600000 || r.OnUnknownEffect != "needsAttention" {
			return fmt.Errorf("invalid bounded recovery policy")
		}
	}
	if p.Constraints != nil {
		for _, r := range p.Constraints.FileRoots {
			if !filepath.IsAbs(r) || filepath.Clean(r) != r {
				return fmt.Errorf("file root must be absolute and clean")
			}
		}
	}
	for _, c := range p.Checkpoints {
		if err := c.Validate(); err != nil {
			return err
		}
	}
	if p.Objective != nil {
		if err := p.checkPredicate(p.Objective); err != nil {
			return err
		}
	}
	for _, a := range p.Artifacts {
		if err := p.checkReference(a.FromPath); err != nil {
			return err
		}
	}
	for _, b := range p.Bindings {
		if b.Value != nil {
			if err := p.checkReference(*b.Value); err != nil {
				return err
			}
		}
		if b.Selector != nil {
			if err := p.checkSelectorReferences(*b.Selector); err != nil {
				return err
			}
		}
	}
	for _, s := range p.Steps {
		if !utf8.ValidString(s.Purpose) || len(s.Purpose) > 1000 {
			return fmt.Errorf("step purpose must be valid UTF-8 and at most 1000 bytes")
		}
		if err := p.checkSelectorReferences(s.Target); err != nil {
			return err
		}
		for _, v := range s.Arguments {
			if err := p.checkReference(v); err != nil {
				return err
			}
		}
		for _, v := range s.Effect.BusinessKey {
			if err := p.checkReference(v); err != nil {
				return err
			}
		}
		if s.Assertion != nil && s.Assertion.Expected != nil {
			if err := p.checkReference(*s.Assertion.Expected); err != nil {
				return err
			}
		}
		for _, pred := range []*Predicate{s.Precondition, s.Postcondition, s.Effect.Reconcile} {
			if pred != nil {
				if err := p.checkPredicate(pred); err != nil {
					return err
				}
			}
		}
		if s.SemanticsProfile != "" && !contains(p.profileNames(), s.SemanticsProfile) {
			return fmt.Errorf("undeclared semantics profile %s", s.SemanticsProfile)
		}
	}
	return nil
}
func (p Plan) profileNames() []string {
	if p.Requires == nil {
		return nil
	}
	return p.Requires.SemanticsProfiles
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func (p Plan) checkPredicate(pred *Predicate) error {
	if err := pred.Validate(); err != nil {
		return err
	}
	if pred.Scope.SurfaceRef != "" {
		if _, ok := p.Surfaces[pred.Scope.SurfaceRef]; !ok {
			return fmt.Errorf("undefined surface %s", pred.Scope.SurfaceRef)
		}
	}
	if pred.Kind == "adapter" && (p.Requires == nil || !contains(p.Requires.Adapters, pred.Adapter)) {
		return fmt.Errorf("undeclared adapter %s", pred.Adapter)
	}
	for _, v := range pred.Inputs {
		if err := p.checkReference(v); err != nil {
			return err
		}
	}
	return nil
}
func (p Plan) checkReference(v Value) error {
	if v.Kind == ReferenceValue {
		parts := strings.Split(v.Ref, ".")
		if len(parts) < 2 || parts[1] == "" {
			return fmt.Errorf("invalid reference")
		}
		switch parts[0] {
		case "input":
			if p.Inputs != nil {
				def, ok := p.Inputs[parts[1]]
				if !ok {
					return fmt.Errorf("undefined input %s", parts[1])
				}
				if len(parts) > 2 && def.Type != ObjectValue && def.Type != ArrayValue {
					return fmt.Errorf("cannot traverse scalar input %s", parts[1])
				}
				if v.Expected != "" && len(parts) == 2 && v.Expected != def.Type {
					return fmt.Errorf("input type mismatch")
				}
			}
		case "artifact":
			if p.Artifacts != nil {
				definition, ok := p.Artifacts[parts[1]]
				if !ok {
					return fmt.Errorf("undefined artifact %s", parts[1])
				}
				if len(parts) > 3 {
					return fmt.Errorf("invalid artifact field")
				}
				if len(parts) == 3 {
					switch parts[2] {
					case "path":
					case "sha256":
						if !contains(definition.Require, "sha256") {
							return fmt.Errorf("artifact digest not required")
						}
					default:
						return fmt.Errorf("unknown artifact field %s", parts[2])
					}
				}
			}
		}
	}
	for _, x := range v.Array {
		if err := p.checkReference(x); err != nil {
			return err
		}
	}
	for _, x := range v.Object {
		if err := p.checkReference(x); err != nil {
			return err
		}
	}
	return nil
}

func (p Plan) checkSelectorReferences(s Selector) error {
	if s.Locator != nil {
		if err := p.checkReference(s.Locator.Value); err != nil {
			return err
		}
		if s.Locator.Name != nil {
			if err := p.checkReference(*s.Locator.Name); err != nil {
				return err
			}
		}
	}
	for _, o := range []map[string]Value{s.Scope.Window, s.Scope.Frame} {
		for _, v := range o {
			if err := p.checkReference(v); err != nil {
				return err
			}
		}
	}
	if s.Ancestor != nil {
		return p.checkSelectorReferences(*s.Ancestor)
	}
	return nil
}

func identifier(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}
