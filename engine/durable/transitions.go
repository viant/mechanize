package durable

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/attachoperation"
	"github.com/viant/mechanize/data/transitionrun"
	integration "github.com/viant/mechanize/integration/endly"
)

// TransitionRun requires an actually inhibited runtime admission context.
func (b *Builder) TransitionRun(ctx context.Context, p auth.Principal, runID string, expectedRevision int, target string) (State, error) {
	return b.transitionRun(ctx, p, runID, expectedRevision, target, nil, nil)
}
func (b *Builder) transitionRun(ctx context.Context, p auth.Principal, runID string, expectedRevision int, target string, proof *data.BusinessVerification, result *integration.BusinessResult) (State, error) {
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
	current, err := load(ctx, user.server, p, runID)
	if err != nil {
		return State{}, err
	}
	sequence := 1
	for _, event := range current.Events {
		if event.Sequence != nil && *event.Sequence >= sequence {
			sequence = *event.Sequence + 1
		}
	}
	var payload []byte
	if proof != nil {
		ctx, err = data.WithBusinessVerification(ctx, *proof)
		if err != nil {
			return State{}, err
		}
		payload, _ = json.Marshal(struct {
			Status string `json:"status"`
			data.BusinessVerification
		}{target, *proof})
	} else if result != nil {
		payload, _ = json.Marshal(struct {
			Status   string                      `json:"status"`
			Business *integration.BusinessResult `json:"business"`
		}{target, result})
	} else {
		payload, _ = json.Marshal(map[string]string{"status": target})
	}
	event := &transitionrun.Event{}
	event.SetNamespace(pointer(p.Namespace))
	event.SetId(pointer(key("transition", runID, target, now())))
	event.SetRunId(pointer(runID))
	event.SetSequence(pointer(sequence))
	event.SetKind(pointer("run_transition"))
	event.SetPayloadJson(pointer(string(payload)))
	event.SetCreatedAt(pointer(now()))
	run := &transitionrun.Run{}
	run.SetNamespace(pointer(p.Namespace))
	run.SetId(pointer(runID))
	run.SetRevision(pointer(expectedRevision))
	run.SetStatus(pointer(target))
	run.SetUpdatedAt(pointer(now()))
	run.SetEvents([]*transitionrun.Event{event})
	input := &transitionrun.TransitionRunInput{}
	input.SetNamespace(p.Namespace)
	input.SetTransitionRun([]*transitionrun.Run{run})
	if _, err = invoke(ctx, user.server, "transitionrun", "TransitionRun", "PATCH", input, true); err != nil {
		return State{}, err
	}
	return stateRead(ctx, user.server, p, runID)
}
func (b *Builder) AttachOperation(ctx context.Context, p auth.Principal, runID string, expectedRevision int, sessionID, operationID string) (State, error) {
	return b.attachOperation(ctx, p, runID, expectedRevision, sessionID, operationID, false)
}

// AttachResumedOperation is called only under Runtime.Resume's held admission gate.
func (b *Builder) AttachResumedOperation(ctx context.Context, p auth.Principal, runID string, expectedRevision int, sessionID, operationID string) (State, error) {
	return b.attachOperation(ctx, p, runID, expectedRevision, sessionID, operationID, true)
}
func (b *Builder) attachOperation(ctx context.Context, p auth.Principal, runID string, expectedRevision int, sessionID, operationID string, resume bool) (State, error) {
	if sessionID == "" || operationID == "" {
		return State{}, errors.New("complete Endly correlation required")
	}
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return State{}, err
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	current, err := load(ctx, user.server, p, runID)
	if err != nil {
		return State{}, err
	}
	if current.EndlySessionId != nil && current.EndlyOperationId != nil && *current.EndlySessionId == sessionID && *current.EndlyOperationId == operationID {
		return stateRead(ctx, user.server, p, runID)
	}
	sequence := 1
	for _, event := range current.Events {
		if event.Sequence != nil && *event.Sequence >= sequence {
			sequence = *event.Sequence + 1
		}
	}
	if resume {
		ctx, err = data.WithResumePermit(ctx, p.Namespace, runID, expectedRevision)
		if err != nil {
			return State{}, err
		}
	}
	payload, _ := json.Marshal(map[string]string{"sessionId": sessionID, "operationId": operationID})
	event := &attachoperation.Event{}
	event.SetNamespace(pointer(p.Namespace))
	event.SetId(pointer(key("operation-attached", runID, sessionID, operationID)))
	event.SetRunId(pointer(runID))
	event.SetSequence(pointer(sequence))
	kind := "operation_attached"
	if resume {
		kind = "operation_resumed"
	}
	event.SetKind(pointer(kind))
	event.SetPayloadJson(pointer(string(payload)))
	event.SetCreatedAt(pointer(now()))
	run := &attachoperation.Run{}
	run.SetNamespace(pointer(p.Namespace))
	run.SetId(pointer(runID))
	run.SetRevision(pointer(expectedRevision))
	if resume {
		run.SetStatus(pointer("running"))
	}
	run.SetEndlySessionId(pointer(sessionID))
	run.SetEndlyOperationId(pointer(operationID))
	run.SetUpdatedAt(pointer(now()))
	run.SetEvents([]*attachoperation.Event{event})
	input := &attachoperation.AttachOperationInput{}
	input.SetNamespace(p.Namespace)
	input.SetAttachOperation([]*attachoperation.Run{run})
	if _, err = invoke(ctx, user.server, "attachoperation", "AttachOperation", "PATCH", input, true); err != nil {
		return State{}, err
	}
	return stateRead(ctx, user.server, p, runID)
}
