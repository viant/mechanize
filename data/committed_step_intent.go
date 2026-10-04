package data

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"

	"github.com/viant/mechanize/auth"
)

// CommittedStepIntent is a scalar snapshot of the already committed attempt.
// ClientID may be empty for legacy non-MCP execution; this is not enrolled MCP
// client qualification. Production binding must separately require that client.
// Trusted engine code supplies it after commit confirmation; request decoding
// cannot produce an active context capability from these record values.
type CommittedStepIntent struct {
	Namespace   string
	ClientID    string
	RunID       string
	PlanID      string
	StepID      string
	StepIndex   int
	AttemptID   string
	EffectID    string
	LeaseEpoch  int
	RunRevision int
	SessionID   string
	OperationID string
}

type committedStepIntentKey struct{}
type committedStepIntentContext struct {
	record CommittedStepIntent
	active atomic.Bool
}

var ErrCommittedStepIntentUnavailable = errors.New("active committed step intent required")

// WithCommittedStepIntent is only for the synchronous committed dispatch call.
// Its returned revoke must run when that call returns, including panic unwinding.
func WithCommittedStepIntent(ctx context.Context, p auth.Principal, record CommittedStepIntent) (context.Context, func(), error) {
	if err := checkCommittedStepIntent(ctx, p, record); err != nil {
		return nil, nil, err
	}
	holder := &committedStepIntentContext{record: record}
	holder.active.Store(true)
	return context.WithValue(ctx, committedStepIntentKey{}, holder), func() { holder.active.Store(false) }, nil
}

// WithoutCommittedStepIntent prevents nested read-only callbacks from inheriting
// a caller's still-active mutation capability. It does not revoke that caller.
func WithoutCommittedStepIntent(ctx context.Context) context.Context {
	return context.WithValue(ctx, committedStepIntentKey{}, (*committedStepIntentContext)(nil))
}

func RequireCommittedStepIntent(ctx context.Context, p auth.Principal) (CommittedStepIntent, error) {
	holder, ok := ctx.Value(committedStepIntentKey{}).(*committedStepIntentContext)
	if !ok || holder == nil || !holder.active.Load() {
		return CommittedStepIntent{}, ErrCommittedStepIntentUnavailable
	}
	record := holder.record
	if err := checkCommittedStepIntent(ctx, p, record); err != nil {
		return CommittedStepIntent{}, err
	}
	if !holder.active.Load() {
		return CommittedStepIntent{}, ErrCommittedStepIntentUnavailable
	}
	return record, nil
}

func checkCommittedStepIntent(ctx context.Context, p auth.Principal, r CommittedStepIntent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || r.Namespace != p.Namespace || r.ClientID != p.ClientID {
		return ErrCommittedStepIntentUnavailable
	}
	scope, err := RequireScope(ctx, p.Namespace)
	if err != nil || r.LeaseEpoch <= 0 || scope.LeaseEpoch != r.LeaseEpoch || r.RunRevision <= 0 || r.StepIndex < 0 {
		return ErrCommittedStepIntentUnavailable
	}
	for _, id := range []string{r.RunID, r.PlanID, r.StepID, r.AttemptID, r.EffectID, r.SessionID, r.OperationID} {
		if len(id) == 0 || len(id) > 256 || strings.TrimSpace(id) != id || strings.ContainsAny(id, "\x00\r\n") {
			return ErrCommittedStepIntentUnavailable
		}
	}
	if len(r.ClientID) > 256 || strings.ContainsAny(r.ClientID, "\x00\r\n") {
		return ErrCommittedStepIntentUnavailable
	}
	return nil
}
