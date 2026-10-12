package consent

import (
	"context"
	"sync"
)

// AuthorizeCleanupObservation preserves an existing approved observation mode
// while machine-only control cleanup is pending. It grants no input, recording,
// consent recovery, or business-effect resolution. Host privacy/exposure gates
// must still run before requesting this lease.
func (s *Service) AuthorizeCleanupObservation(ctx context.Context, op Operation) (*Lease, string, error) {
	c, err := s.client(ctx)
	if err != nil {
		return nil, "", err
	}
	ns, err := s.namespace(ctx)
	if err != nil {
		return nil, "", err
	}
	if op.SessionID != c.SessionID || op.Mode != Observe || op.Scope.Validate() != nil {
		return nil, "", ErrCleanupUnconfirmed
	}
	rows, err := s.read(ctx, "consenttrusted", "*", c.ID)
	if err != nil {
		return nil, "", err
	}
	for _, r := range rows {
		if r.Namespace != ns || r.ClientID != c.ID || !r.permanent() || !r.cleanupMachineOnly || r.GrantState != "active" || r.RevocationState != string(CleanupUnknown) || op.GrantID != "" && op.GrantID != r.GrantID {
			continue
		}
		scope, modes, err := r.details()
		if err != nil || !scope.Covers(op.Scope) {
			continue
		}
		observation := false
		for _, mode := range modes {
			observation = observation || mode == Observe
		}
		if !observation || s.policy(ctx, c, r) != nil || s.options.Policy(ctx, c, op.Scope, []Mode{Observe}, r.DurationSeconds) != nil {
			continue
		}
		token, err := randomID()
		if err != nil {
			return nil, "", err
		}
		key := ns + ":" + r.GrantID
		owned, cancel := context.WithCancel(ctx)
		s.mu.Lock()
		if s.humanBlocked[key] || ctx.Err() != nil {
			s.mu.Unlock()
			cancel()
			return nil, "", ErrCleanupUnconfirmed
		}
		if s.active[key] == nil {
			s.active[key] = map[string]context.CancelFunc{}
		}
		if s.bindings[key] == nil {
			s.bindings[key] = map[string]Client{}
		}
		s.active[key][token] = cancel
		s.bindings[key][token] = c
		s.mu.Unlock()
		var once sync.Once
		release := func() {
			once.Do(func() {
				cancel()
				s.mu.Lock()
				defer s.mu.Unlock()
				delete(s.active[key], token)
				delete(s.bindings[key], token)
			})
		}
		return &Lease{Context: owned, Release: release}, r.GrantID, nil
	}
	return nil, "", ErrCleanupUnconfirmed
}
