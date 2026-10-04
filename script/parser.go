// Package script implements a closed DSL frontend. It never evaluates host code.
package script

import (
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/model"
	"strconv"
	"strings"
	"unicode"
)

type Error struct {
	Stage    string
	Position model.SourceSpan
	Message  string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s:%d:%d: %s", e.Stage, e.Position.Line, e.Position.Column, e.Message)
}

type token struct {
	kind, text string
	pos        model.SourceSpan
}
type Argument struct {
	Name string
	Expr *Expression
}
type Call struct {
	Name     string
	Args     []Argument
	Position model.SourceSpan
}
type Expression struct {
	Elements  []*Expression
	Fields    map[string]*Expression
	Composite model.ValueKind
	Literal   *model.Value
	Root      string
	Calls     []Call
	Position  model.SourceSpan
}
type Instruction struct {
	Bind     string
	Expr     *Expression
	Position model.SourceSpan
}
type Program struct{ Instructions []Instruction }
type Parser struct{}

func (Parser) Parse(source string) (*Program, error) { return Parse(source) }
func Parse(source string) (*Program, error) {
	if len(source) > 1<<20 {
		return nil, &Error{"parse", model.SourceSpan{Line: 1, Column: 1}, "source exceeds 1 MiB"}
	}
	ts, err := lex(source)
	if err != nil {
		return nil, err
	}
	p := parser{tokens: ts}
	result := &Program{}
	for p.peek().kind != "eof" {
		if p.peek().kind == "newline" || p.peek().kind == ";" {
			p.i++
			continue
		}
		in := Instruction{Position: p.peek().pos}
		if p.peek().text == "let" {
			p.i++
			n := p.take()
			if n.kind != "ident" {
				return nil, p.fail(n, "expected binding name")
			}
			in.Bind = n.text
			if err = p.require("="); err != nil {
				return nil, err
			}
		}
		in.Expr, err = p.expression()
		if err != nil {
			return nil, err
		}
		result.Instructions = append(result.Instructions, in)
		if k := p.peek().kind; k != "newline" && k != ";" && k != "eof" {
			return nil, p.fail(p.peek(), "unexpected trailing input; separate instructions with a newline or semicolon")
		}
	}
	return result, nil
}

type parser struct {
	tokens []token
	i      int
	depth  int
}

func (p *parser) peek() token { return p.tokens[p.i] }
func (p *parser) take() token {
	t := p.peek()
	if t.kind != "eof" {
		p.i++
	}
	return t
}
func (p *parser) fail(t token, s string) error { return &Error{"parse", t.pos, s} }
func (p *parser) require(k string) error {
	t := p.take()
	if t.kind != k {
		return p.fail(t, "expected "+k)
	}
	return nil
}
func (p *parser) expression() (*Expression, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 64 {
		return nil, p.fail(p.peek(), "expression nesting exceeds 64")
	}
	t := p.take()
	e := &Expression{Position: t.pos}
	switch t.kind {
	case "[", "{":
		end := "]"
		e.Composite = model.ArrayValue
		if t.kind == "{" {
			end = "}"
			e.Composite = model.ObjectValue
			e.Fields = map[string]*Expression{}
		}
		for p.peek().kind != end {
			key := ""
			if t.kind == "{" {
				k := p.take()
				if k.kind != "string" {
					return nil, p.fail(k, "object keys must be JSON strings")
				}
				var err error
				err = json.Unmarshal([]byte(k.text), &key)
				if err != nil {
					return nil, p.fail(k, "invalid object key")
				}
				if _, ok := e.Fields[key]; ok {
					return nil, p.fail(k, "duplicate object key")
				}
				if err = p.require(":"); err != nil {
					return nil, err
				}
			}
			child, err := p.expression()
			if err != nil {
				return nil, err
			}
			if t.kind == "[" {
				e.Elements = append(e.Elements, child)
			} else {
				e.Fields[key] = child
			}
			if p.peek().kind != "," {
				break
			}
			p.i++
			if p.peek().kind == end {
				return nil, p.fail(p.peek(), "trailing comma is unsupported")
			}
		}
		if err := p.require(end); err != nil {
			return nil, err
		}
	case "string":
		var s string
		err := json.Unmarshal([]byte(t.text), &s)
		if err != nil {
			return nil, p.fail(t, "invalid JSON string escape")
		}
		e.Literal = &model.Value{Kind: model.StringValue, String: s}
	case "number":
		n, err := strconv.ParseInt(t.text, 10, 64)
		if err != nil {
			return nil, p.fail(t, "integer out of range")
		}
		e.Literal = &model.Value{Kind: model.NumberValue, Number: n}
	case "duration":
		var factor int64
		v := t.text
		switch {
		case strings.HasSuffix(v, "ms"):
			factor = 1
			v = strings.TrimSuffix(v, "ms")
		case strings.HasSuffix(v, "s"):
			factor = 1000
			v = strings.TrimSuffix(v, "s")
		case strings.HasSuffix(v, "m"):
			factor = 60000
			v = strings.TrimSuffix(v, "m")
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 || n > 3600000/factor {
			return nil, p.fail(t, "duration must be between 1ms and 60m")
		}
		e.Literal = &model.Value{Kind: model.DurationValue, Number: n * factor}
	case "$":
		n := p.take()
		if n.kind != "ident" || (n.text != "input" && n.text != "artifact" && n.text != "run") {
			return nil, p.fail(n, "references must start with $input, $artifact or $run")
		}
		path := n.text
		for p.peek().kind == "." {
			p.i++
			n = p.take()
			if n.kind != "ident" {
				return nil, p.fail(n, "expected reference field")
			}
			path += "." + n.text
		}
		if !strings.Contains(path, ".") {
			return nil, p.fail(t, "reference requires a field")
		}
		e.Literal = &model.Value{Kind: model.ReferenceValue, Ref: path}
	case "ident":
		if t.text == "true" || t.text == "false" {
			e.Literal = &model.Value{Kind: model.BoolValue, Bool: t.text == "true"}
			break
		}
		e.Root = t.text
		if p.peek().kind == "(" {
			c, err := p.call(t)
			if err != nil {
				return nil, err
			}
			e.Calls = append(e.Calls, c)
		}
	default:
		return nil, p.fail(t, "expected value, scope or locator; host JavaScript and shell syntax are unsupported")
	}
	for e.Literal == nil && e.Composite == "" && p.peek().kind == "." {
		p.i++
		n := p.take()
		if n.kind != "ident" {
			return nil, p.fail(n, "expected method name")
		}
		if n.text == "not" && p.peek().kind == "." {
			e.Calls = append(e.Calls, Call{Name: "not", Position: n.pos})
			continue
		}
		c, err := p.call(n)
		if err != nil {
			return nil, err
		}
		e.Calls = append(e.Calls, c)
	}
	return e, nil
}
func (p *parser) call(n token) (Call, error) {
	c := Call{Name: n.text, Position: n.pos}
	if err := p.require("("); err != nil {
		return c, err
	}
	named := false
	seen := map[string]bool{}
	for p.peek().kind != ")" {
		a := Argument{}
		if p.peek().kind == "ident" && p.tokens[p.i+1].kind == ":" {
			a.Name = p.take().text
			p.i++
			named = true
			if seen[a.Name] {
				return c, p.fail(p.peek(), "duplicate option "+a.Name)
			}
			seen[a.Name] = true
		} else if named {
			return c, p.fail(p.peek(), "positional argument cannot follow named options")
		}
		var err error
		a.Expr, err = p.expression()
		if err != nil {
			return c, err
		}
		c.Args = append(c.Args, a)
		if p.peek().kind != "," {
			break
		}
		p.i++
		if p.peek().kind == ")" {
			return c, p.fail(p.peek(), "trailing comma is unsupported")
		}
	}
	return c, p.require(")")
}
func lex(s string) ([]token, error) {
	var ts []token
	line, col := 1, 1
	for i := 0; i < len(s); {
		start := i
		pos := model.SourceSpan{Offset: i, Line: line, Column: col}
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' {
			i++
			col++
			continue
		}
		if c == '/' && i+1 < len(s) && s[i+1] == '/' {
			for i < len(s) && s[i] != '\n' {
				i++
				col++
			}
			continue
		}
		k := ""
		switch {
		case c == '\n':
			k = "newline"
			i++
			line++
			col = 1
		case c == '"':
			i++
			for i < len(s) && s[i] != '"' && s[i] != '\n' {
				if s[i] == '\\' {
					i++
					if i >= len(s) {
						break
					}
				}
				i++
			}
			if i >= len(s) || s[i] != '"' {
				return nil, &Error{"parse", pos, "unterminated string"}
			}
			i++
			k = "string"
			col += i - start
		case c >= '0' && c <= '9' || c == '-':
			i++
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++
			}
			k = "number"
			for i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
				i++
				k = "duration"
			}
			if k == "duration" && !strings.HasSuffix(s[start:i], "ms") && !strings.HasSuffix(s[start:i], "s") && !strings.HasSuffix(s[start:i], "m") {
				return nil, &Error{"parse", pos, "unsupported duration unit"}
			}
			col += i - start
		case unicode.IsLetter(rune(c)) || c == '_':
			i++
			for i < len(s) && (s[i] == '_' || s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z' || s[i] >= '0' && s[i] <= '9') {
				i++
			}
			k = "ident"
			col += i - start
		case strings.ContainsRune("().,:=$;[]{}", rune(c)):
			k = string(c)
			i++
			col++
		default:
			return nil, &Error{"parse", pos, "unsupported token " + strconv.Quote(string(c))}
		}
		ts = append(ts, token{k, s[start:i], pos})
	}
	ts = append(ts, token{"eof", "", model.SourceSpan{Offset: len(s), Line: line, Column: col}})
	return ts, nil
}
