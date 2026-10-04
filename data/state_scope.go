package data

import (
	"context"
	"errors"
)

type statePermitKey struct{}
type statePermit struct{ namespace, runID string }

// WithStateMutationPermit is trusted host metadata. Its caller must hold the
// runtime's paused/new run admission lock through commit and state refresh.
func WithStateMutationPermit(ctx context.Context, namespace, runID string) (context.Context, error) {
	if _, err := RequireScope(ctx, namespace); err != nil {
		return nil, err
	}
	if runID == "" {
		return nil, errors.New("state run identity required")
	}
	return context.WithValue(ctx, statePermitKey{}, statePermit{namespace, runID}), nil
}
func RequireStateMutationPermit(ctx context.Context, namespace, runID string) error {
	if _, err := RequireScope(ctx, namespace); err != nil {
		return err
	}
	permit, ok := ctx.Value(statePermitKey{}).(statePermit)
	if !ok || permit.namespace != namespace || permit.runID != runID {
		return errors.New("safe paused/new runtime state mutation context required")
	}
	return nil
}
