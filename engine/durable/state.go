package durable

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/viant/datly/standalone"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/stateget"
	"github.com/viant/mechanize/data/statepatch"
	"github.com/viant/mechanize/model"
)

// StatePatchCommittedError reports committed durable values that need runtime
// attention. It never implies rollback or permits automatic patch replay.
type StatePatchCommittedError struct {
	State State
	Cause error
}

func (e *StatePatchCommittedError) Error() string {
	return "stateCommittedNeedsAttention: durable state committed; runtime bindings require attention"
}
func (e *StatePatchCommittedError) Unwrap() error         { return e.Cause }
func (e *StatePatchCommittedError) CommittedState() State { return e.State }

var ErrStatePatchUnavailable = errors.New("safe paused/new runtime state mutation integration is unavailable")

type State struct {
	// NeedsAttention is transient runtime refresh metadata, not a persisted run status.
	NeedsAttention    bool                         `json:"needsAttention,omitempty"`
	RunID             string                       `json:"runId"`
	PlanID            string                       `json:"planId"`
	ObjectiveID       string                       `json:"objectiveId"`
	SessionID         string                       `json:"sessionId,omitempty"`
	OperationID       string                       `json:"operationId,omitempty"`
	Status            string                       `json:"status"`
	Revision          int                          `json:"revision"`
	Variables         map[string]model.Value       `json:"variables"`
	Progress          []*stateget.Milestone        `json:"progress"`
	UnresolvedEffects []*stateget.UnresolvedEffect `json:"unresolvedEffects"`
	Checkpoints       []*stateget.Checkpoint       `json:"checkpoints"`
}

func stateRead(ctx context.Context, server *standalone.Server, p auth.Principal, runID string) (State, error) {
	input := &stateget.StateGetInput{}
	input.SetNamespace(p.Namespace)
	input.SetRunID(runID)
	value, err := invoke(ctx, server, "stateget", "StateGet", "GET", input, false)
	if err != nil {
		return State{}, err
	}
	output, ok := value.(*stateget.StateGetOutput)
	if !ok || len(output.Data) != 1 {
		return State{}, errors.New("authorized run state not found")
	}
	row := output.Data[0]
	if row.Id == nil || row.PlanId == nil || row.ObjectiveId == nil || row.Status == nil || row.Revision == nil {
		return State{}, errors.New("incomplete persisted run state")
	}
	result := State{RunID: *row.Id, PlanID: *row.PlanId, ObjectiveID: *row.ObjectiveId, Status: *row.Status, Revision: *row.Revision, Variables: map[string]model.Value{}, Progress: row.Milestones, UnresolvedEffects: row.Unresolved, Checkpoints: row.Checkpoints}
	if row.EndlySessionId != nil {
		result.SessionID = *row.EndlySessionId
	}
	if row.EndlyOperationId != nil {
		result.OperationID = *row.EndlyOperationId
	}
	for _, variable := range row.Variables {
		if variable.Name == nil || variable.ValueJson == nil {
			return State{}, errors.New("invalid persisted variable")
		}
		var value model.Value
		if err = json.Unmarshal([]byte(*variable.ValueJson), &value); err != nil {
			return State{}, errors.New("invalid persisted variable JSON")
		}
		if err = value.Validate(); err != nil {
			return State{}, err
		}
		result.Variables[*variable.Name] = value
	}
	return result, nil
}

// StateGet invokes the one generated authorized state projection component.
func (b *Builder) StateGet(ctx context.Context, p auth.Principal, runID string) (State, error) {
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return State{}, err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	return stateRead(ctx, user.server, p, runID)
}

// StatePatch changes typed user variables only. Its host guard must inhibit
// admission until the committed values are refreshed into the paused context.
// Nil guard fails closed; no state API can clear effects or alter history.
func (b *Builder) StatePatch(ctx context.Context, p auth.Principal, runID string, expectedRevision int, variables map[string]model.Value) (State, error) {
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return State{}, err
	}
	if b.options.StateMutationGuard == nil {
		return State{}, ErrStatePatchUnavailable
	}
	release, err := b.options.StateMutationGuard(ctx, p, runID)
	if err != nil {
		return State{}, err
	}
	if release == nil {
		return State{}, ErrStatePatchUnavailable
	}
	defer release()
	user.mu.Lock()
	defer user.mu.Unlock()
	ctx, err = data.WithStateMutationPermit(ctx, p.Namespace, runID)
	if err != nil {
		return State{}, err
	}
	if expectedRevision <= 0 || len(variables) == 0 || len(variables) > 128 {
		return State{}, errors.New("expected revision and 1...128 variables required")
	}
	previous, err := validateStateVariablesLocked(ctx, user.server, p, runID, variables)
	if err != nil {
		return State{}, err
	}
	names := make([]string, 0, len(variables))
	for name := range variables {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]*statepatch.Variable, 0, len(names))
	for _, name := range names {
		value := variables[name]
		if err = value.Validate(); err != nil {
			return State{}, err
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return State{}, err
		}
		row := &statepatch.Variable{}
		row.SetNamespace(pointer(p.Namespace))
		row.SetRunId(pointer(runID))
		row.SetName(pointer(name))
		row.SetValueJson(pointer(string(encoded)))
		rows = append(rows, row)
	}
	run := &statepatch.RunState{}
	run.SetNamespace(pointer(p.Namespace))
	run.SetId(pointer(runID))
	run.SetRevision(pointer(expectedRevision))
	run.SetVariables(rows)
	input := &statepatch.StatePatchInput{}
	input.SetNamespace(p.Namespace)
	input.SetStatePatch([]*statepatch.RunState{run})
	if _, err = invoke(ctx, user.server, "statepatch", "StatePatch", "PATCH", input, true); err != nil {
		return State{}, err
	}
	state, err := stateRead(ctx, user.server, p, runID)
	if err != nil {
		// Invoke confirmed the commit; a failed projection cannot undo it.
		state = previous
		state.Revision = expectedRevision + 1
		state.NeedsAttention = true
		for name, value := range variables {
			state.Variables[name] = value
		}
		return state, &StatePatchCommittedError{State: state, Cause: err}
	}
	if b.options.RefreshVariables != nil {
		if err = b.options.RefreshVariables(ctx, p, runID, state.Variables); err != nil {
			state.NeedsAttention = true
			return state, &StatePatchCommittedError{State: state, Cause: err}
		}
	}
	return state, nil
}
