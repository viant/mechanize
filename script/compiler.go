package script

import (
	"fmt"
	"github.com/viant/mechanize/model"
)

type Compiler struct{}

func Compile(source string) (*model.Plan, error) {
	p, e := Parse(source)
	if e != nil {
		return nil, e
	}
	return (Compiler{}).TypeCheck(p)
}
func (Compiler) Normalize(p *Program) (*model.Plan, error) {
	plan, err := (Compiler{}).TypeCheck(p)
	if err != nil {
		return nil, err
	}
	for i := range plan.Steps {
		plan.Steps[i].Source = model.SourceSpan{}
	}
	return plan, nil
}

type typed struct {
	kind     string
	selector model.Selector
	value    model.Value
}
type compiler struct {
	symbols map[string]typed
	plan    *model.Plan
}

func (Compiler) TypeCheck(p *Program) (*model.Plan, error) { return typeCheck(p, nil) }
func (Compiler) TypeCheckWithBindings(p *Program, bindings []model.Binding) (*model.Plan, error) {
	return typeCheck(p, bindings)
}
func typeCheck(p *Program, bindings []model.Binding) (*model.Plan, error) {
	if p == nil {
		return nil, fmt.Errorf("nil program")
	}
	c := compiler{symbols: map[string]typed{}, plan: &model.Plan{SchemaVersion: 1, Steps: []model.Step{}, Bindings: []model.Binding{}}}
	for _, b := range bindings {
		if reserved(b.Name) {
			return nil, fmt.Errorf("reserved binding %s", b.Name)
		}
		if _, ok := c.symbols[b.Name]; ok {
			return nil, fmt.Errorf("duplicate binding %s", b.Name)
		}
		v := typed{kind: b.Type}
		if b.Value != nil {
			v.value = *b.Value
		}
		if b.Selector != nil {
			v.selector = *b.Selector
		}
		c.symbols[b.Name] = v
		c.plan.Bindings = append(c.plan.Bindings, b)
	}
	for _, in := range p.Instructions {
		if in.Bind != "" {
			if reserved(in.Bind) {
				return nil, c.err(in.Position, "reserved binding name "+in.Bind)
			}
			if _, ok := c.symbols[in.Bind]; ok {
				return nil, c.err(in.Position, "binding already defined: "+in.Bind)
			}
		}
		v, s, e := c.eval(in.Expr)
		if e != nil {
			return nil, e
		}
		if s != nil {
			s.ID = fmt.Sprintf("step-%d", len(c.plan.Steps)+1)
			s.Source = in.Position
			if in.Bind != "" {
				if v.kind != "value" {
					return nil, c.err(in.Position, "only a read result may bind an executed action")
				}
				s.Bind = in.Bind
			}
			c.plan.Steps = append(c.plan.Steps, *s)
		}
		if in.Bind != "" {
			c.symbols[in.Bind] = v
			b := model.Binding{Name: in.Bind, Type: v.kind}
			if v.kind == "value" {
				vv := v.value
				b.Value = &vv
			} else {
				ss := v.selector
				b.Selector = &ss
			}
			c.plan.Bindings = append(c.plan.Bindings, b)
		} else if s == nil {
			return nil, c.err(in.Position, "unused descriptor or value; bind it with let")
		}
	}
	return c.plan, c.plan.Validate()
}
func reserved(s string) bool {
	switch s {
	case "app", "web", "desktop", "expect", "input", "artifact", "run", "let", "true", "false", "pointer", "keyboard", "checkpoint", "outcome":
		return true
	}
	return false
}
func (c *compiler) err(p model.SourceSpan, s string) error { return &Error{"typecheck", p, s} }
func (c *compiler) value(e *Expression) (model.Value, error) {
	v, step, err := c.eval(e)
	if err != nil {
		return model.Value{}, err
	}
	if step != nil || v.kind != "value" {
		return model.Value{}, c.err(e.Position, "expected scalar value; nested actions and descriptors are forbidden")
	}
	return v.value, nil
}
func (c *compiler) args(call Call, positional int, opts map[string]model.ValueKind) ([]model.Value, map[string]model.Value, error) {
	var vs []model.Value
	ns := map[string]model.Value{}
	for _, a := range call.Args {
		v, e := c.value(a.Expr)
		if e != nil {
			return nil, nil, e
		}
		if a.Name == "" {
			vs = append(vs, v)
		} else {
			k, ok := opts[a.Name]
			if !ok {
				return nil, nil, c.err(call.Position, "unknown option "+a.Name+" for "+call.Name)
			}
			if v.Kind != k && v.Kind != model.ReferenceValue || v.Kind == model.ReferenceValue && v.Expected != "" && v.Expected != k {
				return nil, nil, c.err(a.Expr.Position, "option "+a.Name+" requires "+string(k))
			}
			if v.Kind == model.ReferenceValue {
				v.Expected = k
			}
			ns[a.Name] = v
		}
	}
	if len(vs) != positional {
		return nil, nil, c.err(call.Position, fmt.Sprintf("%s requires %d positional argument(s)", call.Name, positional))
	}
	return vs, ns, nil
}
func (c *compiler) text(v model.Value, p model.SourceSpan) (string, error) {
	if v.Kind != model.StringValue {
		return "", c.err(p, "surface identities require literal strings")
	}
	if v.String == "" {
		return "", c.err(p, "empty identity is invalid")
	}
	return v.String, nil
}
func (c *compiler) eval(e *Expression) (typed, *model.Step, error) {
	if e == nil {
		return typed{}, nil, fmt.Errorf("nil expression")
	}
	if e.Composite != "" {
		val := model.Value{Kind: e.Composite}
		for _, x := range e.Elements {
			v, err := c.value(x)
			if err != nil {
				return typed{}, nil, err
			}
			val.Array = append(val.Array, v)
		}
		if e.Fields != nil {
			val.Object = map[string]model.Value{}
			for key, x := range e.Fields {
				v, err := c.value(x)
				if err != nil {
					return typed{}, nil, err
				}
				val.Object[key] = v
			}
		}
		return typed{kind: "value", value: val}, nil, nil
	}
	if e.Literal != nil {
		return typed{kind: "value", value: *e.Literal}, nil, nil
	}
	var v typed
	idx := 0
	switch e.Root {
	case "app":
		if len(e.Calls) == 0 || e.Calls[0].Name != "app" {
			return v, nil, c.err(e.Position, "app requires a bundle ID")
		}
		a, process, err := c.args(e.Calls[0], 1, map[string]model.ValueKind{"processId": model.NumberValue, "processStartToken": model.StringValue})
		if err != nil {
			return v, nil, err
		}
		bundle, err := c.text(a[0], e.Position)
		if err != nil {
			return v, nil, err
		}
		surface := model.Surface{Kind: "native", BundleID: bundle}
		if pid, ok := process["processId"]; ok {
			if pid.Kind != model.NumberValue || pid.Number <= 0 || pid.Number > 2147483647 {
				return v, nil, c.err(e.Position, "processId requires a positive literal PID")
			}
			surface.ProcessID = int(pid.Number)
		}
		if token, ok := process["processStartToken"]; ok {
			surface.ProcessStartToken, err = c.text(token, e.Position)
			if err != nil {
				return v, nil, err
			}
		}
		if err = surface.ValidateProcessIdentity(); err != nil {
			return v, nil, c.err(e.Position, err.Error())
		}
		v = typed{kind: "app", selector: model.Selector{Surface: surface, Cardinality: "one"}}
		idx = 1
	case "web":
		if len(e.Calls) == 0 || e.Calls[0].Name != "tab" {
			return v, nil, c.err(e.Position, "web requires tab(...)")
		}
		_, o, err := c.args(e.Calls[0], 0, map[string]model.ValueKind{"origin": model.StringValue, "title": model.StringValue, "id": model.StringValue})
		if err != nil {
			return v, nil, err
		}
		s := model.Surface{Kind: "web"}
		for k, x := range o {
			str, err := c.text(x, e.Position)
			if err != nil {
				return v, nil, err
			}
			switch k {
			case "origin":
				s.Origin = str
			case "title":
				s.Title = str
			case "id":
				s.TabID = str
			}
		}
		if s.Origin == "" && s.TabID == "" {
			return v, nil, c.err(e.Position, "web.tab requires origin or id")
		}
		v = typed{kind: "page", selector: model.Selector{Surface: s, Cardinality: "one"}}
		idx = 1
	case "expect":
		return c.expect(e)
	default:
		var ok bool
		v, ok = c.symbols[e.Root]
		if !ok {
			return v, nil, c.err(e.Position, "unknown binding or namespace "+e.Root)
		}
		if v.kind == "value" {
			expected := v.value.Kind
			if expected == model.ReferenceValue {
				expected = v.value.Expected
			}
			v.value = model.Value{Kind: model.ReferenceValue, Ref: "binding." + e.Root, Expected: expected}
		}
	}
	for ; idx < len(e.Calls); idx++ {
		call := e.Calls[idx]
		switch call.Name {
		case "menuBar", "focusedElement":
			if v.kind != "app" || v.selector.Surface.Kind != "native" || v.selector.Locator != nil || v.selector.Ancestor != nil || v.selector.Scope.NativeRoot != "" || len(v.selector.Scope.Window) != 0 || len(v.selector.Scope.Frame) != 0 {
				return v, nil, c.err(call.Position, "native root requires an unscoped app receiver")
			}
			if _, _, err := c.args(call, 0, map[string]model.ValueKind{}); err != nil {
				return v, nil, err
			}
			v.selector.Scope.NativeRoot = call.Name
		case "window", "frame":
			if v.selector.Scope.NativeRoot != "" {
				return v, nil, c.err(call.Position, "native root cannot mix window or frame scopes")
			}
			if call.Name == "window" && v.kind != "app" || call.Name == "frame" && v.kind != "page" {
				return v, nil, c.err(call.Position, "invalid scope receiver for "+call.Name)
			}
			allowed := map[string]model.ValueKind{"title": model.StringValue, "role": model.StringValue, "documentKey": model.StringValue}
			if call.Name == "frame" {
				allowed = map[string]model.ValueKind{"id": model.StringValue, "name": model.StringValue}
			}
			_, o, err := c.args(call, 0, allowed)
			if err != nil {
				return v, nil, err
			}
			if len(o) == 0 {
				return v, nil, c.err(call.Position, "scope narrowing requires an option")
			}
			if call.Name == "window" {
				v.selector.Scope.Window = o
				v.kind = "window"
			} else {
				v.selector.Scope.Frame = o
				v.kind = "frame"
			}
		case "getByRole", "getByName", "getById", "getByTestId", "getByLabel", "getByText":
			if v.kind == "value" {
				return v, nil, c.err(call.Position, "locator requires a scope")
			}
			a, o, err := c.args(call, 1, map[string]model.ValueKind{"exact": model.BoolValue, "name": model.StringValue})
			if err != nil {
				return v, nil, err
			}
			if !stringLike(a[0]) {
				return v, nil, c.err(call.Position, "locator requires string")
			}
			strategy := map[string]string{"getByRole": "role", "getByName": "name", "getById": "id", "getByTestId": "testId", "getByLabel": "label", "getByText": "text"}[call.Name]
			if _, ok := o["name"]; ok && strategy != "role" {
				return v, nil, c.err(call.Position, "name option is only valid for getByRole")
			}
			if v.kind == "locator" {
				parent := v.selector
				v.selector.Ancestor = &parent
			}
			if a[0].Kind == model.ReferenceValue {
				a[0].Expected = model.StringValue
			}
			loc := &model.Locator{Strategy: strategy, Value: a[0], Exact: strategy == "id" || strategy == "testId"}
			if x, ok := o["name"]; ok {
				loc.Name = &x
			}
			if x, ok := o["exact"]; ok {
				if x.Kind != model.BoolValue {
					return v, nil, c.err(call.Position, "exact must be a literal boolean")
				}
				loc.Exact = x.Bool
			}
			v.selector.Locator = loc
			v.kind = "locator"

		case "within":
			if v.kind != "locator" || len(call.Args) != 1 || call.Args[0].Name != "" {
				return v, nil, c.err(call.Position, "within requires locator receiver and one scoped locator")
			}
			parent, st, err := c.eval(call.Args[0].Expr)
			if err != nil {
				return v, nil, err
			}
			if st != nil || parent.kind != "locator" || parent.selector.Surface != v.selector.Surface {
				return v, nil, c.err(call.Position, "within requires same-surface locator descriptor")
			}
			copy := parent.selector
			v.selector.Ancestor = &copy
		case "all", "nth":
			if v.kind != "locator" || v.selector.Cardinality != "one" {
				return v, nil, c.err(call.Position, "cardinality modifier requires strict locator")
			}
			n := 0
			options := map[string]model.ValueKind{"limit": model.NumberValue, "order": model.StringValue}
			if call.Name == "nth" {
				n = 1
				delete(options, "limit")
			}
			a, o, err := c.args(call, n, options)
			if err != nil {
				return v, nil, err
			}
			order := ""
			if x, ok := o["order"]; ok {
				order, err = c.text(x, call.Position)
				if err != nil {
					return v, nil, err
				}
			}
			v.selector.Order = order
			if call.Name == "all" {
				limit, ok := o["limit"]
				if !ok || limit.Kind != model.NumberValue || limit.Number < 1 || limit.Number > 1000 {
					return v, nil, c.err(call.Position, "all requires limit 1..1000")
				}
				v.selector.Cardinality = "all"
				v.selector.Limit = int(limit.Number)
			} else {
				if a[0].Kind != model.NumberValue || a[0].Number < 0 || a[0].Number > 999 || order == "" {
					return v, nil, c.err(call.Position, "nth requires index 0..999 and explicit order")
				}
				index := int(a[0].Number)
				v.selector.Cardinality = "nth"
				v.selector.Index = &index
			}
			if err := v.selector.Validate(); err != nil {
				return v, nil, c.err(call.Position, err.Error())
			}
		case "clickWindowFrame":
			if v.kind != "app" || idx != len(e.Calls)-1 {
				return v, nil, c.err(call.Position, "window frame click requires app receiver and must terminate chain")
			}
			_, options, err := c.args(call, 0, map[string]model.ValueKind{"captureRef": model.StringValue, "x": model.NumberValue, "y": model.NumberValue, "timeout": model.DurationValue})
			if err != nil {
				return v, nil, err
			}
			frame := map[string]model.Value{}
			for _, key := range []string{"captureRef", "x", "y"} {
				value, ok := options[key]
				if !ok {
					return v, nil, c.err(call.Position, "captureRef, x and y named arguments required")
				}
				frame[key] = value
			}
			step := &model.Step{Action: "window.clickFrame", Target: v.selector, Arguments: map[string]model.Value{"frameClick": {Kind: model.ObjectValue, Object: frame}}, TimeoutMs: 15000, Effect: model.Effect{Class: model.ExternalNonIdempotent}}
			if timeout, ok := options["timeout"]; ok {
				step.TimeoutMs = timeout.Number
			}
			return typed{kind: "void"}, step, nil
		case "pressWindowKey":
			if v.kind != "app" || idx != len(e.Calls)-1 {
				return v, nil, c.err(call.Position, "window key requires app receiver and must terminate chain")
			}
			_, options, err := c.args(call, 0, map[string]model.ValueKind{"windowId": model.NumberValue, "key": model.StringValue, "timeout": model.DurationValue})
			if err != nil {
				return v, nil, err
			}
			windowID, idOK := options["windowId"]
			key, keyOK := options["key"]
			if !idOK || !keyOK {
				return v, nil, c.err(call.Position, "windowId and key named arguments required")
			}
			step := &model.Step{Action: "window.pressSessionKey", Target: v.selector, Arguments: map[string]model.Value{"windowKey": {Kind: model.ObjectValue, Object: map[string]model.Value{"windowId": windowID, "key": key}}}, TimeoutMs: 15000, Effect: model.Effect{Class: model.ExternalNonIdempotent}}
			if timeout, ok := options["timeout"]; ok {
				if timeout.Kind != model.DurationValue {
					return v, nil, c.err(call.Position, "timeout requires duration literal")
				}
				step.TimeoutMs = timeout.Number
			}
			return typed{kind: "void"}, step, nil
		case "open", "activate", "focus", "click", "submit", "fill", "read", "check", "uncheck", "select", "pressKey", "pressSessionKey", "moveTo", "replaceText":
			validReceiver := v.kind == "locator" && call.Name != "open" && call.Name != "activate" || v.kind == "app" && (call.Name == "open" || call.Name == "activate")
			if !validReceiver || idx != len(e.Calls)-1 {
				return v, nil, c.err(call.Position, "action requires its registered receiver and must terminate chain")
			}
			definition, _ := model.ActionByMethod(call.Name)
			n := 0
			if definition.Argument != "" {
				n = 1
			}
			a, o, err := c.args(call, n, map[string]model.ValueKind{"timeout": model.DurationValue})
			if err != nil {
				return v, nil, err
			}
			step := &model.Step{Action: definition.Action, Target: v.selector, Arguments: map[string]model.Value{}, TimeoutMs: 15000, Effect: model.Effect{Class: model.ExternalNonIdempotent}}
			if call.Name == "activate" {
				step.Effect.BusinessKey = map[string]model.Value{"bundleID": {Kind: model.StringValue, String: step.Target.Surface.BundleID}}
			}
			if x, ok := o["timeout"]; ok {
				if x.Kind != model.DurationValue {
					return v, nil, c.err(call.Position, "timeout requires duration literal")
				}
				step.TimeoutMs = x.Number
			}
			if n == 1 {
				if a[0].Kind != definition.ArgumentType && a[0].Kind != model.ReferenceValue || a[0].Kind == model.ReferenceValue && a[0].Expected != "" && a[0].Expected != definition.ArgumentType {
					return v, nil, c.err(call.Position, "action argument requires "+string(definition.ArgumentType))
				}
				if a[0].Kind == model.ReferenceValue {
					a[0].Expected = definition.ArgumentType
				}
				step.Arguments[definition.Argument] = a[0]
			}
			v.kind = "void"
			if definition.ReadOnly {
				step.Effect.Class = model.ReadOnly
			}
			if call.Name == "read" {
				attr, err := c.text(a[0], call.Position)
				if err != nil {
					return v, nil, err
				}
				kind := model.StringValue
				switch attr {
				case "text", "value", "name":
				case "staticText", "identifier", "role":
					if step.Target.Surface.Kind != "native" {
						return v, nil, c.err(call.Position, "native metadata/text read requires native surface")
					}
				case "focused", "enabled":
					if step.Target.Surface.Kind != "native" {
						return v, nil, c.err(call.Position, "native boolean read requires native surface")
					}
					kind = model.BoolValue
				case "checked":
					kind = model.BoolValue
				default:
					return v, nil, c.err(call.Position, "unsupported read attribute")
				}
				if step.Target.Cardinality == "all" {
					kind = model.ArrayValue
				}
				step.ResultType = kind
				v = typed{kind: "value", value: model.Value{Kind: model.ReferenceValue, Expected: kind, Ref: fmt.Sprintf("step.step-%d.result", len(c.plan.Steps)+1)}}
			}
			return v, step, nil

		default:
			return v, nil, c.err(call.Position, "unsupported method "+call.Name)
		}
	}
	return v, nil, nil
}
func (c *compiler) expect(e *Expression) (typed, *model.Step, error) {
	v := typed{kind: "void"}
	if len(e.Calls) < 2 || e.Calls[0].Name != "expect" || len(e.Calls[0].Args) != 1 || e.Calls[0].Args[0].Name != "" {
		return v, nil, c.err(e.Position, "expect requires one target and a matcher")
	}
	t, s, err := c.eval(e.Calls[0].Args[0].Expr)
	if err != nil {
		return v, nil, err
	}
	if s != nil || t.kind == "value" {
		return v, nil, c.err(e.Position, "expect target must be a scope or locator")
	}
	i := 1
	negative := false
	if e.Calls[i].Name == "not" {
		negative = true
		i++
	}
	if i != len(e.Calls)-1 {
		return v, nil, c.err(e.Position, "expect requires exactly one matcher")
	}
	m := e.Calls[i]
	n := 0
	switch m.Name {
	case "toBeVisible", "toBeEnabled", "toBeChecked":
	case "toHaveText", "toHaveValue":
		n = 1
		if t.kind != "locator" {
			return v, nil, c.err(m.Position, "value matcher requires locator")
		}
	default:
		return v, nil, c.err(m.Position, "unsupported matcher "+m.Name)
	}
	a, o, err := c.args(m, n, map[string]model.ValueKind{"timeout": model.DurationValue})
	if err != nil {
		return v, nil, err
	}
	st := &model.Step{Action: "expect", Target: t.selector, Arguments: map[string]model.Value{}, TimeoutMs: 5000, Effect: model.Effect{Class: model.ReadOnly}, Assertion: &model.Assertion{Matcher: m.Name, Not: negative}}
	if n == 1 {
		if !stringLike(a[0]) {
			return v, nil, c.err(m.Position, "matcher requires string or reference")
		}
		if a[0].Kind == model.ReferenceValue {
			a[0].Expected = model.StringValue
		}
		st.Assertion.Expected = &a[0]
	}
	if x, ok := o["timeout"]; ok {
		if x.Kind != model.DurationValue {
			return v, nil, c.err(m.Position, "timeout requires a duration literal")
		}
		st.TimeoutMs = x.Number
	}
	return v, st, nil
}

func stringLike(v model.Value) bool {
	return v.Kind == model.StringValue || v.Kind == model.ReferenceValue && (v.Expected == "" || v.Expected == model.StringValue)
}
