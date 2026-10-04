package model

// Resolve returns a fresh selector after resolving every typed locator/scope value.
func (s Selector) Resolve(bindings map[string]Value) (Selector, error) {
	if err := s.Validate(); err != nil {
		return Selector{}, err
	}
	return resolveSelector(s, bindings)
}
func resolveSelector(s Selector, bindings map[string]Value) (Selector, error) {
	if s.Locator != nil {
		loc := *s.Locator
		v, err := ResolveValue(loc.Value, bindings)
		if err != nil {
			return Selector{}, err
		}
		loc.Value = v
		if loc.Name != nil {
			x, err := ResolveValue(*loc.Name, bindings)
			if err != nil {
				return Selector{}, err
			}
			loc.Name = &x
		}
		s.Locator = &loc
	}
	for i, m := range []map[string]Value{s.Scope.Window, s.Scope.Frame} {
		if m == nil {
			continue
		}
		out := make(map[string]Value, len(m))
		for k, v := range m {
			x, err := ResolveValue(v, bindings)
			if err != nil {
				return Selector{}, err
			}
			out[k] = x
		}
		if i == 0 {
			s.Scope.Window = out
		} else {
			s.Scope.Frame = out
		}
	}
	if s.Ancestor != nil {
		ancestor, err := resolveSelector(*s.Ancestor, bindings)
		if err != nil {
			return Selector{}, err
		}
		s.Ancestor = &ancestor
	}
	return s, s.Validate()
}
