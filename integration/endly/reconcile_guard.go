package endly

import (
	"context"
	"errors"

	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
)

// ReconciliationGuard holds admission only after all live operations are
// terminal. The host additionally holds the physical input fence. A restarted
// runtime alone cannot attest that old native helpers have stopped.
func (r *Runtime) ReconciliationGuard(ctx context.Context, p auth.Principal, runID string) (func(), error) {
	release, err := r.StateMutationGuard(ctx, p, runID)
	if err != nil {
		return nil, err
	}
	type operationRef struct {
		session, id string
		ready       <-chan struct{}
	}
	var operations []operationRef
	r.mu.RLock()
	for _, program := range r.programs {
		if program.operationID != "" {
			operations = append(operations, operationRef{program.owner, program.operationID, program.objectiveReady})
		}
	}
	r.mu.RUnlock()
	for _, ref := range operations {
		op, err := r.manager.GetOperation(ref.session, ref.id)
		if err != nil {
			release()
			return nil, err
		}
		switch op.Status {
		case manager.OperationCancelled, manager.OperationFailed, manager.OperationSucceeded:
		default:
			release()
			return nil, errors.New("overlapping operation has not stopped")
		}
		if ref.ready != nil {
			select {
			case <-ref.ready:
			case <-ctx.Done():
				release()
				return nil, ctx.Err()
			}
		}
	}
	return release, nil
}
