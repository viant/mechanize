package endly

import (
	"context"
	"errors"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"time"
)

type EvaluatePostcondition func(context.Context, auth.Principal, model.Predicate, map[string]model.Value) (objective.Result, error)
type CompletionRequest struct {
	Metadata        ExecutionMetadata
	Plan            model.Plan
	Values          map[string]model.Value
	OperationStatus string
}
type BusinessResult struct {
	BusinessStatus    string            `json:"businessStatus"`
	VerificationState string            `json:"verificationState"`
	Objective         *objective.Result `json:"objective,omitempty"`
	Reason            string            `json:"reason,omitempty"`
}
type CompleteObjective func(context.Context, auth.Principal, CompletionRequest) (BusinessResult, error)

// observeCompletion observes Endly's terminal operation. It never schedules an
// action, retries an effect, or substitutes dispatch status for business truth.
func (r *Runtime) observeCompletion(ctx context.Context, runID string, p *program) {
	r.mu.Lock()
	p.objectiveReady = make(chan struct{})
	ready := p.objectiveReady
	session, operation := p.owner, p.operationID
	budget := 35 * time.Second
	for _, step := range p.plan.Steps {
		budget += time.Duration(step.TimeoutMs) * time.Millisecond
		for _, predicate := range []*model.Predicate{step.Precondition, step.Postcondition} {
			if predicate != nil {
				budget += time.Duration(predicate.TimeoutMs) * time.Millisecond
			}
		}
	}
	if budget > 24*time.Hour {
		budget = 24 * time.Hour
	}
	observeCtx, observeCancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
	p.objectiveCancel = observeCancel
	r.mu.Unlock()
	go func() {
		defer observeCancel()
		result := BusinessResult{BusinessStatus: "unverified", VerificationState: "unverified", Reason: "qualified objective completion is unavailable"}
		finished, err := r.manager.WaitOperation(observeCtx, session, operation)
		if err == nil && r.completeObjective != nil {
			r.mu.RLock()
			values := make(map[string]model.Value, len(p.values))
			for k, v := range p.values {
				values[k] = v
			}
			actor := p.requestPrincipal
			if actor.Validate() != nil {
				actor = r.principals[session]
			}
			request := CompletionRequest{Metadata: ExecutionMetadata{RunID: runID, PlanID: p.planID, SessionID: session}, Plan: p.plan, Values: values, OperationStatus: finished.Status}
			r.mu.RUnlock()
			finalCtx, cancel := context.WithTimeout(auth.WithPrincipal(context.WithoutCancel(ctx), actor), 35*time.Second)
			result, err = r.completeObjective(finalCtx, actor, request)
			cancel()
		}
		if err != nil {
			result = BusinessResult{BusinessStatus: "unverified", VerificationState: "unknown", Reason: "objective completion could not be durably verified"}
		}
		// A callback cannot report success for an unsuccessful Endly operation.
		if result.BusinessStatus == "succeeded" && (finished == nil || finished.Status != manager.OperationSucceeded || result.Objective == nil || objective.RequireBusinessSuccess(*result.Objective) != nil || p.plan.Objective == nil || time.Since(result.Objective.ObservedAt) > time.Duration(p.plan.Objective.FreshnessMs)*time.Millisecond) {
			result = BusinessResult{BusinessStatus: "unverified", VerificationState: "unknown", Reason: "business success contract is incomplete"}
		}
		r.mu.Lock()
		p.businessResult = result
		close(ready)
		r.mu.Unlock()
	}()
}

// Result returns the separate business outcome for this owned live operation.
// Pending completion remains unverified even if Endly has just completed.
func (r *Runtime) Result(ctx context.Context, session, operation string) (BusinessResult, error) {
	if _, err := r.authorize(ctx, session); err != nil {
		return BusinessResult{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.programs {
		if p.owner == session && p.operationID == operation {
			if p.objectiveReady != nil {
				select {
				case <-p.objectiveReady:
					return p.businessResult, nil
				default:
				}
			}
			return BusinessResult{BusinessStatus: "unverified", VerificationState: "pending"}, nil
		}
	}
	return BusinessResult{}, errors.New("operation has no live business outcome mapping")
}

func (r *Runtime) waitObjective(ctx context.Context, session, operation string) error {
	r.mu.RLock()
	var ready chan struct{}
	for _, p := range r.programs {
		if p.owner == session && p.operationID == operation {
			ready = p.objectiveReady
			break
		}
	}
	r.mu.RUnlock()
	if ready != nil {
		select {
		case <-ready:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
