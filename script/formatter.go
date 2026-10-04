package script

import (
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/model"
	"sort"
	"strings"
)

type Formatter struct{}

func (Formatter) Print(p *Program) string {
	var lines []string
	for _, in := range p.Instructions {
		s := printExpr(in.Expr)
		if in.Bind != "" {
			s = "let " + in.Bind + " = " + s
		}
		lines = append(lines, s)
	}
	return strings.Join(lines, "\n")
}
func quote(s string) string { b, _ := json.Marshal(s); return string(b) }
func printExpr(e *Expression) string {
	if e.Literal != nil {
		v := e.Literal
		switch v.Kind {
		case model.StringValue:
			return quote(v.String)
		case model.BoolValue:
			return fmt.Sprint(v.Bool)
		case model.NumberValue:
			return fmt.Sprint(v.Number)
		case model.DurationValue:
			return fmt.Sprintf("%dms", v.Number)
		case model.ReferenceValue:
			return "$" + v.Ref
		}
	}
	if e.Composite == model.ArrayValue {
		var vs []string
		for _, x := range e.Elements {
			vs = append(vs, printExpr(x))
		}
		return "[" + strings.Join(vs, ", ") + "]"
	}
	if e.Composite == model.ObjectValue {
		var keys []string
		for k := range e.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var vs []string
		for _, k := range keys {
			vs = append(vs, quote(k)+": "+printExpr(e.Fields[k]))
		}
		return "{" + strings.Join(vs, ", ") + "}"
	}
	s := e.Root
	for i, c := range e.Calls {
		if i == 0 && c.Name == e.Root {
			s = ""
		} else {
			s += "."
		}
		s += c.Name
		if c.Name == "not" {
			continue
		}
		var args []string
		for _, a := range c.Args {
			x := printExpr(a.Expr)
			if a.Name != "" {
				x = a.Name + ": " + x
			}
			args = append(args, x)
		}
		s += "(" + strings.Join(args, ", ") + ")"
	}
	return s
}
