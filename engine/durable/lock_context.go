package durable

import (
	"context"
	"errors"
	"sync"

	"github.com/viant/mechanize/auth"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
)

type heldUserLockKey struct{}

// This package-private capability exists only during a trusted callback while
// Execute holds user.mu. The gate drains nested invocations before revocation,
// so a captured context cannot borrow a lock after the callback has returned.
type heldUserLock struct {
	gate                sync.Mutex
	active              bool
	builder             *Builder
	user                *userHost
	namespace, clientID string
}

var errHeldUserLockExpired = errors.New("scoped durable invocation is no longer active")

func (b *Builder) withHeldUserLock(ctx context.Context, p auth.Principal, user *userHost) (context.Context, func()) {
	held := &heldUserLock{active: true, builder: b, user: user, namespace: p.Namespace, clientID: p.ClientID}
	return context.WithValue(ctx, heldUserLockKey{}, held), func() {
		held.gate.Lock()
		held.active = false
		held.gate.Unlock()
	}
}

func (b *Builder) heldInvocation(ctx context.Context, p auth.Principal) (*userHost, func(), bool, error) {
	held, ok := ctx.Value(heldUserLockKey{}).(*heldUserLock)
	if !ok {
		return nil, nil, false, nil
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || held.builder != b || held.namespace != actual.Namespace || held.clientID != actual.ClientID {
		return nil, nil, true, auth.ErrUnauthorized
	}
	held.gate.Lock()
	if !held.active {
		held.gate.Unlock()
		return nil, nil, true, errHeldUserLockExpired
	}
	if err = ctx.Err(); err != nil {
		held.gate.Unlock()
		return nil, nil, true, err
	}
	return held.user, held.gate.Unlock, true, nil
}

func (b *Builder) dispatchWhileLocked(ctx context.Context, p auth.Principal, user *userHost, step model.Step, values map[string]model.Value) (integration.StepResult, error) {
	callbackCtx, revoke := b.withHeldUserLock(ctx, p, user)
	defer revoke()
	return b.dispatch(callbackCtx, p, step, values)
}
func (b *Builder) evaluateWhileLocked(ctx context.Context, p auth.Principal, user *userHost, predicate model.Predicate, values map[string]model.Value) (objective.Result, error) {
	callbackCtx, revoke := b.withHeldUserLock(ctx, p, user)
	defer revoke()
	return b.EvaluatePostcondition(callbackCtx, p, predicate, values)
}
