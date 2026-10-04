package endly

import (
	"context"
	"fmt"

	endlylib "github.com/viant/endly"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

type stepRequest struct {
	ProgramID string `json:"programId"`
	StepID    string `json:"stepId"`
}

func (r *stepRequest) Validate() error {
	if r.ProgramID == "" || r.StepID == "" {
		return fmt.Errorf("programId and stepId required")
	}
	return nil
}

type service struct {
	*endlylib.AbstractService
	runtime *Runtime
}

func newService(r *Runtime) endlylib.Service {
	s := &service{AbstractService: endlylib.NewAbstractService("mechanize"), runtime: r}
	s.AbstractService.Service = s
	s.Register(&endlylib.Route{Action: "step", RequestProvider: func() interface{} { return &stepRequest{} }, ResponseProvider: func() interface{} { return &StepResult{} }, Handler: func(ctx *endlylib.Context, request interface{}) (interface{}, error) {
		return s.step(ctx, request.(*stepRequest))
	}})
	return s
}
func (s *service) step(ctx *endlylib.Context, request *stepRequest) (interface{}, error) {
	r := s.runtime
	r.mu.Lock()
	p, ok := r.programs[request.ProgramID]
	actor, actorOK := r.principals[ctx.SessionID]
	if !ok || !actorOK || p.owner != ctx.SessionID {
		r.mu.Unlock()
		return nil, auth.ErrUnauthorized
	}
	var selected *model.Step
	stepIndex := 0
	for i := range p.plan.Steps {
		if p.plan.Steps[i].ID == request.StepID {
			stepIndex = i
			candidate := p.plan.Steps[i]
			selected = &candidate
			break
		}
	}
	values := make(map[string]model.Value, len(p.values))
	for k, v := range p.values {
		values[k] = v
	}
	r.mu.Unlock()
	if p.ready != nil {
		select {
		case <-p.ready:
		case <-ctx.Background().Done():
			return nil, ctx.Background().Err()
		}
		if p.admissionErr != nil {
			return nil, p.admissionErr
		}
	}
	if err := ctx.Background().Err(); err != nil {
		return nil, err
	}
	if selected == nil {
		return nil, fmt.Errorf("step not found")
	}
	// The manager replaces Background for operation cancellation. Identity comes
	// from trusted session binding, never from workflow variables or action input.
	if p.requestPrincipal.Validate() == nil {
		actor = p.requestPrincipal
	}
	background := auth.WithPrincipal(ctx.Background(), actor)
	if p.consentBinding.SessionID != "" && p.consentBinding.Purpose != "" {
		background = auth.WithConsentBinding(background, p.consentBinding)
	}
	operationID := ""
	if p.ready != nil {
		operationID = p.operationID
	}
	background = context.WithValue(background, executionKey{}, ExecutionMetadata{Resumed: p.resumed, OperationID: operationID, RunID: request.ProgramID, PlanID: p.planID, SessionID: ctx.SessionID, StepIndex: stepIndex})
	result, err := r.execute(background, actor, *selected, values)
	if err != nil {
		return nil, err
	}
	if selected.Bind != "" && result.Value != nil {
		r.mu.Lock()
		p.values["binding."+selected.Bind] = *result.Value
		r.captureOutput(p, *selected, *result.Value)
		r.mu.Unlock()
	}
	if selected.Postcondition != nil {
		if r.evaluatePostcondition == nil {
			return result, fmt.Errorf("qualified postcondition evaluator unavailable")
		}
		values = make(map[string]model.Value)
		r.mu.RLock()
		for k, v := range p.values {
			values[k] = v
		}
		r.mu.RUnlock()
		var verified objective.Result
		if result.Postcondition != nil {
			verified = *result.Postcondition
		} else {
			var evalErr error
			verified, evalErr = r.evaluatePostcondition(background, actor, *selected.Postcondition, values)
			if evalErr != nil {
				return result, evalErr
			}
			result.Postcondition = &verified
		}
		if verified.Truth != objective.True {
			return result, fmt.Errorf("step postcondition is %s", verified.Truth)
		}
	}
	return result, nil
}
