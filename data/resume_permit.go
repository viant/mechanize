package data

import (
	"context"
	"errors"
)

type resumePermitKey struct{}
type resumePermit struct {
	Namespace, RunID string
	Revision         int
}

// WithResumePermit is issued by the trusted Endly reconstruction boundary after
// admission is inhibited; it is not a client field or a blanket scope bypass.
func WithResumePermit(ctx context.Context, namespace, runID string, revision int) (context.Context, error) {
	if _, err := RequireScope(ctx, namespace); err != nil {
		return nil, err
	}
	if runID == "" || revision <= 0 {
		return nil, errors.New("resume identity/revision required")
	}
	return context.WithValue(ctx, resumePermitKey{}, resumePermit{namespace, runID, revision}), nil
}
func RequireResumePermit(ctx context.Context, namespace, runID string, revision int) error {
	if _, err := RequireScope(ctx, namespace); err != nil {
		return err
	}
	p, ok := ctx.Value(resumePermitKey{}).(resumePermit)
	if !ok || p.Namespace != namespace || p.RunID != runID || p.Revision != revision {
		return errors.New("trusted resume boundary required")
	}
	return nil
}
