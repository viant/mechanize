package endly

import (
	"context"
	"sync/atomic"

	"github.com/viant/mechanize/auth"
)

type sessionCloseContextKey struct{}
type sessionCloseContext struct {
	runtime                    *Runtime
	namespace, client, session string
	active                     atomic.Bool
}

// Only Close creates this callback-bounded identity. It grants no ordinary
// session admission, input authority, or access to another client's session.
func (r *Runtime) sessionCloseContext(ctx context.Context, p auth.Principal, id string) (context.Context, func()) {
	owned := &sessionCloseContext{runtime: r, namespace: p.Namespace, client: p.ClientID, session: id}
	owned.active.Store(true)
	return context.WithValue(ctx, sessionCloseContextKey{}, owned), func() { owned.active.Store(false) }
}

// CheckClosingSession is for trusted lifecycle cleanup inside OnSessionClose.
// CheckSession continues to reject this session for all normal operations.
func (r *Runtime) CheckClosingSession(ctx context.Context, p auth.Principal, id string) error {
	actual, err := auth.FromContext(ctx)
	owned, ok := ctx.Value(sessionCloseContextKey{}).(*sessionCloseContext)
	if err != nil || !ok || owned.runtime != r || !owned.active.Load() || owned.namespace != p.Namespace || owned.client != p.ClientID || owned.session != id || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || ctx.Err() != nil {
		return auth.ErrUnauthorized
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	owner, ok := r.principals[id]
	if !ok || !r.closingSessions[id] || owner.Namespace != p.Namespace || owner.ClientID != p.ClientID {
		return auth.ErrUnauthorized
	}
	return nil
}

// CheckPredecessorSessionStopped is an internal lifecycle query. The host supplies
// the predecessor tuple from its retained verified credential session, never from
// a tool argument. Close keeps principals/closingSessions until manager cleanup has
// finished, so closing and in-flight owners remain ineligible. A host restart has
// no retained predecessor session and cannot use mere map absence as this proof.
func (r *Runtime) CheckPredecessorSessionStopped(ctx context.Context, p auth.Principal, namespace, client, session string) error {
	actual, e := auth.FromContext(ctx)
	if r == nil || e != nil || ctx.Err() != nil || p.Validate() != nil || actual.Validate() != nil || !actual.HasScope("desktop:control") || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || !p.HasScope("desktop:control") || namespace != p.Namespace || client == "" || client == p.ClientID || session == "" {
		return auth.ErrUnauthorized
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, present := r.principals[session]; present || r.closingSessions[session] {
		return auth.ErrUnauthorized
	}
	for _, held := range r.manager.Sessions().Sessions {
		if held.SessionID == session {
			return auth.ErrUnauthorized
		}
	}
	return ctx.Err()
}
