package script

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/model"
	"gopkg.in/yaml.v3"
	"io"
	"sort"
	"strconv"
	"strings"
)

const maxEnvelopeBytes = 1 << 20

func readEnvelope(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxEnvelopeBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxEnvelopeBytes {
		return nil, fmt.Errorf("envelope exceeds 1 MiB")
	}
	return b, nil
}

// DecodeJSON accepts a strict workflow envelope or canonical Plan and normalizes commands.
func DecodeJSON(r io.Reader) (*model.Plan, error) {
	b, err := readEnvelope(r)
	if err != nil {
		return nil, err
	}
	if err = checkJSON(b); err != nil {
		return nil, err
	}
	return decodeEnvelope(b)
}
func decodeEnvelope(b []byte) (*model.Plan, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	p := &model.Plan{}
	if err := d.Decode(p); err != nil {
		return nil, err
	}
	return NormalizeEnvelope(p)
}

// DecodeYAML rejects aliases, custom tags, duplicate keys, multiple documents and excessive nesting.
// It converts scalar data to JSON before invoking the same strict typed decoder.
func DecodeYAML(r io.Reader) (*model.Plan, error) {
	b, err := readEnvelope(r)
	if err != nil {
		return nil, err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	var n yaml.Node
	if err = d.Decode(&n); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err = d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("YAML must contain exactly one document")
	}
	count := 0
	v, err := yamlValue(&n, 0, &count)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return decodeEnvelope(data)
}
func yamlValue(n *yaml.Node, depth int, count *int) (any, error) {
	*count++
	if depth > 64 || *count > 100000 {
		return nil, fmt.Errorf("YAML exceeds nesting/node limit")
	}
	if n.Anchor != "" || n.Kind == yaml.AliasNode {
		return nil, fmt.Errorf("YAML anchors and aliases are unsupported")
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return nil, fmt.Errorf("empty YAML document")
		}
		return yamlValue(n.Content[0], depth+1, count)
	case yaml.MappingNode:
		if n.Tag != "!!map" {
			return nil, fmt.Errorf("custom YAML tag")
		}
		m := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
				return nil, fmt.Errorf("YAML object keys must be strings")
			}
			if _, ok := m[k.Value]; ok {
				return nil, fmt.Errorf("duplicate YAML key %s", k.Value)
			}
			v, e := yamlValue(n.Content[i+1], depth+1, count)
			if e != nil {
				return nil, e
			}
			m[k.Value] = v
		}
		return m, nil
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return nil, fmt.Errorf("custom YAML tag")
		}
		a := make([]any, len(n.Content))
		for i, x := range n.Content {
			v, e := yamlValue(x, depth+1, count)
			if e != nil {
				return nil, e
			}
			a[i] = v
		}
		return a, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str":
			return n.Value, nil
		case "!!bool":
			return strconv.ParseBool(n.Value)
		case "!!int":
			v, e := strconv.ParseInt(n.Value, 10, 64)
			if e != nil {
				return nil, fmt.Errorf("YAML integers must be decimal int64")
			}
			return v, nil
		case "!!null":
			return nil, nil
		default:
			return nil, fmt.Errorf("unsupported YAML scalar tag %s", n.Tag)
		}
	}
	return nil, fmt.Errorf("unsupported YAML node")
}
func checkJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	count := 0
	if err := jsonValue(d, 0, &count); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON input")
	}
	return nil
}
func jsonValue(d *json.Decoder, depth int, count *int) error {
	*count++
	if depth > 64 || *count > 100000 {
		return fmt.Errorf("JSON exceeds nesting/node limit")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return fmt.Errorf("invalid or duplicate JSON key %v", k)
			}
			seen[key] = true
			if e = jsonValue(d, depth+1, count); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e := jsonValue(d, depth+1, count); e != nil {
				return e
			}
		}
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
	_, err = d.Token()
	return err
}

// NormalizeEnvelope compiles each command to one typed step, preserving immutable metadata.
// It does not execute, retry or schedule anything.
func NormalizeEnvelope(input *model.Plan) (*model.Plan, error) {
	if input == nil {
		return nil, fmt.Errorf("nil envelope")
	}
	p := *input
	p.Steps = make([]model.Step, 0, len(input.Steps))
	p.Bindings = append([]model.Binding{}, input.Bindings...)
	if p.Name != "" || p.Inputs != nil || p.Objective != nil || p.Surfaces != nil || p.Artifacts != nil {
		if p.Inputs == nil {
			p.Inputs = map[string]model.InputDefinition{}
		}
		if p.Artifacts == nil {
			p.Artifacts = map[string]model.ArtifactDefinition{}
		}
	}
	aliases := make([]string, 0, len(p.Surfaces))
	for name := range p.Surfaces {
		aliases = append(aliases, name)
	}
	sort.Strings(aliases)
	for _, name := range aliases {
		s := p.Surfaces[name]
		kind := "app"
		if s.Kind == "web" {
			kind = "page"
		}
		selector := model.Selector{Surface: s, Cardinality: "one"}
		existing := false
		for _, b := range p.Bindings {
			if b.Name == name {
				if b.Type != kind || b.Selector == nil || b.Selector.Surface != s || b.Selector.Locator != nil || b.Value != nil {
					return nil, fmt.Errorf("surface alias collides with binding %s", name)
				}
				existing = true
				break
			}
		}
		if !existing {
			p.Bindings = append(p.Bindings, model.Binding{Name: name, Type: kind, Selector: &selector})
		}
	}

	for _, raw := range input.Steps {
		if raw.Command == "" {
			p.Steps = append(p.Steps, raw)
			continue
		}
		if raw.Action != "" || raw.Target.Surface.Kind != "" || len(raw.Arguments) > 0 || raw.Assertion != nil {
			return nil, fmt.Errorf("step %s mixes command with canonical action", raw.ID)
		}
		if raw.ID == "" {
			return nil, fmt.Errorf("workflow command needs step ID")
		}
		ast, err := Parse(raw.Command)
		if err != nil {
			return nil, err
		}
		if len(ast.Instructions) != 1 {
			return nil, fmt.Errorf("workflow command must contain one instruction")
		}
		seedLen := len(p.Bindings)
		compiled, err := (Compiler{}).TypeCheckWithBindings(ast, p.Bindings)
		if err != nil {
			return nil, err
		}
		if len(compiled.Steps) != 1 {
			return nil, fmt.Errorf("workflow command must produce one step")
		}
		s := compiled.Steps[0]
		oldID := s.ID
		s.ID = raw.ID
		s.SemanticsProfile = raw.SemanticsProfile
		s.Precondition = raw.Precondition
		s.Postcondition = raw.Postcondition
		s.Checkpoint = raw.Checkpoint
		s.Purpose = raw.Purpose
		if raw.TimeoutMs != 0 {
			s.TimeoutMs = raw.TimeoutMs
		}
		if raw.Effect.Class != "" && raw.Effect.Class != s.Effect.Class {
			return nil, fmt.Errorf("command effect cannot be downgraded")
		}
		s.Effect.BusinessKey = raw.Effect.BusinessKey
		s.Effect.Reconcile = raw.Effect.Reconcile
		p.Bindings = compiled.Bindings
		for i := seedLen; i < len(p.Bindings); i++ {
			if p.Bindings[i].Value != nil {
				v := *p.Bindings[i].Value
				v = renameStepRef(v, oldID, s.ID)
				p.Bindings[i].Value = &v
			}
		}
		p.Steps = append(p.Steps, s)
	}
	return &p, p.Validate()
}
func renameStepRef(v model.Value, old, new string) model.Value {
	if v.Kind == model.ReferenceValue && strings.HasPrefix(v.Ref, "step."+old+".") {
		v.Ref = "step." + new + strings.TrimPrefix(v.Ref, "step."+old)
	}
	for i, x := range v.Array {
		v.Array[i] = renameStepRef(x, old, new)
	}
	for k, x := range v.Object {
		v.Object[k] = renameStepRef(x, old, new)
	}
	return v
}
