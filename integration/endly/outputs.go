package endly

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

const maxOutputBindings = 16
const maxOutputBytes = 8192
const maxOperationOutputBytes = 65536

type runtimeOutput struct {
	value  model.Value
	reason string
	bytes  int
}

// OperationOutputs is an ephemeral snapshot, not a durable checkpoint. Only
// explicitly requested completed element.read bindings can appear in Outputs.
type OperationOutputs struct {
	SessionID   string                 `json:"sessionId"`
	OperationID string                 `json:"operationId"`
	RunID       string                 `json:"runId"`
	Storage     string                 `json:"storage"`
	Outputs     map[string]model.Value `json:"outputs"`
	Unavailable map[string]string      `json:"unavailable,omitempty"`
}

func ValidateOutputBindings(bindings []string) error {
	if len(bindings) == 0 || len(bindings) > maxOutputBindings {
		return errors.New("1...16 explicit read binding names required")
	}
	seen := map[string]bool{}
	for _, name := range bindings {
		if name == "" || len(name) > 128 || seen[name] {
			return errors.New("bounded unique read binding names required")
		}
		for i, c := range name {
			if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
				return errors.New("read binding names must be identifiers without a namespace prefix")
			}
		}
		seen[name] = true
	}
	return nil
}

// OperationOutputs reads only this client's owned, completed live operation.
// Runtime shutdown/restart or session close discards these values.
func (r *Runtime) OperationOutputs(ctx context.Context, session, operation string, bindings []string) (OperationOutputs, error) {
	if session == "" || operation == "" || len(session) > 256 || len(operation) > 256 {
		return OperationOutputs{}, errors.New("bounded sessionId and operationId required")
	}
	if err := ValidateOutputBindings(bindings); err != nil {
		return OperationOutputs{}, err
	}
	actor, err := auth.FromContext(ctx)
	if err != nil {
		return OperationOutputs{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	owner, ok := r.principals[session]
	if !ok || owner.Namespace != actor.Namespace || owner.ClientID != actor.ClientID {
		return OperationOutputs{}, auth.ErrUnauthorized
	}
	var p *program
	runID := ""
	for id, candidate := range r.programs {
		if candidate.owner == session && candidate.operationID == operation {
			p = candidate
			runID = id
			break
		}
	}
	if p == nil {
		return OperationOutputs{}, errors.New("operation outputs unavailable: no owned live operation mapping")
	}
	op, err := r.manager.GetOperation(session, operation)
	if err != nil {
		return OperationOutputs{}, errors.New("operation outputs unavailable: operation not found")
	}
	if op.Status != manager.OperationSucceeded {
		return OperationOutputs{}, fmt.Errorf("operation outputs unavailable: execution status %s; successful completion required", op.Status)
	}
	response := OperationOutputs{SessionID: session, OperationID: operation, RunID: runID, Storage: "ephemeralRuntime", Outputs: map[string]model.Value{}, Unavailable: map[string]string{}}
	for _, name := range bindings {
		read := false
		for _, step := range p.plan.Steps {
			if step.Bind == name && step.Action == "element.read" {
				read = true
				break
			}
		}
		if !read {
			return OperationOutputs{}, errors.New("requested binding is not a read output")
		}
		output, ok := p.outputs[name]
		if !ok {
			response.Unavailable[name] = "completed read produced no retained safe output"
			continue
		}
		if output.reason != "" {
			response.Unavailable[name] = output.reason
			continue
		}
		// Retained values have already passed strict structural and byte limits.
		body, _ := json.Marshal(output.value)
		var copied model.Value
		if err := json.Unmarshal(body, &copied); err != nil {
			return OperationOutputs{}, errors.New("runtime output copy unavailable")
		}
		response.Outputs[name] = copied
	}
	return response, nil
}

// captureOutput runs under r.mu. Never resolve runtime references for export.
func (r *Runtime) captureOutput(p *program, step model.Step, value model.Value) {
	if step.Action != "element.read" || step.Bind == "" {
		return
	}
	if p.outputs == nil {
		p.outputs = map[string]runtimeOutput{}
	}
	if _, ok := p.outputs[step.Bind]; !ok && len(p.outputs) >= 32 {
		return
	}
	entry := runtimeOutput{reason: "read output withheld: sensitive or exceeds export limits"}
	secrets := []string{}
	sensitiveBounded := true
	secretNodes := 0
	for name, definition := range p.plan.Inputs {
		if definition.Sensitive || sensitiveOutputName(name) {
			if v, ok := p.values["input."+name]; ok {
				sensitiveBounded = collectOutputSecrets(v, &secrets, 0, &secretNodes) && sensitiveBounded
			}
			if definition.Default != nil {
				sensitiveBounded = collectOutputSecrets(*definition.Default, &secrets, 0, &secretNodes) && sensitiveBounded
			}
		}
	}
	for name, v := range p.values {
		if strings.HasPrefix(name, "input.") && sensitiveOutputName(name) {
			sensitiveBounded = collectOutputSecrets(v, &secrets, 0, &secretNodes) && sensitiveBounded
		}
	}
	nodes := 0
	safe := sensitiveBounded && !sensitiveOutputName(step.Bind)
	targetBody, _ := json.Marshal(step.Target)
	// A protected selector must not be exported even if its executor supplies a value.
	for _, marker := range []string{"password", "credential", "secret", "securetextfield"} {
		if strings.Contains(strings.ToLower(string(targetBody)), marker) {
			safe = false
		}
	}
	if safe && safeOutputValue(value, secrets, 0, &nodes) {
		body, err := json.Marshal(value)
		total := 0
		for name, v := range p.outputs {
			if name != step.Bind {
				total += v.bytes
			}
		}
		if err == nil && len(body) <= maxOutputBytes && total+len(body) <= maxOperationOutputBytes {
			var copied model.Value
			if json.Unmarshal(body, &copied) == nil {
				entry = runtimeOutput{value: copied, bytes: len(body)}
			}
		}
	}
	p.outputs[step.Bind] = entry
}
func sensitiveOutputName(name string) bool {
	name = strings.ToLower(name)
	for _, marker := range []string{"password", "passwd", "credential", "secret", "token", "authorization", "apikey", "api_key"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}
func collectOutputSecrets(v model.Value, out *[]string, depth int, nodes *int) bool {
	*nodes++
	if *nodes > 256 || depth > 8 || len(*out) >= 256 || len(v.Array) > 256 || len(v.Object) > 256 || v.Kind == model.ReferenceValue {
		return false
	}
	if v.Kind == model.NumberValue || v.Kind == model.DurationValue {
		*out = append(*out, fmt.Sprint(v.Number))
	}
	if v.String != "" {
		*out = append(*out, v.String)
	}
	for _, item := range v.Array {
		if !collectOutputSecrets(item, out, depth+1, nodes) {
			return false
		}
	}
	for _, item := range v.Object {
		if !collectOutputSecrets(item, out, depth+1, nodes) {
			return false
		}
	}
	return true
}
func safeOutputValue(v model.Value, secrets []string, depth int, nodes *int) bool {
	*nodes++
	if depth > 8 || *nodes > 256 || len(v.String) > maxOutputBytes || len(v.Array) > 256 || len(v.Object) > 256 || v.Kind == model.ReferenceValue {
		return false
	}
	shallow := v
	if shallow.Kind == model.ArrayValue {
		shallow.Array = []model.Value{}
	}
	if shallow.Kind == model.ObjectValue {
		shallow.Object = map[string]model.Value{}
	}
	if shallow.Validate() != nil {
		return false
	}
	for _, secret := range secrets {
		if strings.Contains(v.String, secret) || (v.Kind == model.NumberValue || v.Kind == model.DurationValue) && fmt.Sprint(v.Number) == secret {
			return false
		}
	}
	for _, item := range v.Array {
		if !safeOutputValue(item, secrets, depth+1, nodes) {
			return false
		}
	}
	for name, item := range v.Object {
		if len(name) > 128 || sensitiveOutputName(name) || !safeOutputValue(item, secrets, depth+1, nodes) {
			return false
		}
	}
	return true
}
