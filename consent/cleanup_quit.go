package consent

import (
	"context"
	"sync"
)

// AuthorizeCleanupQuit is a host-only grant for normal Chrome termination. The
// host must restrict its use to an exact PID/birth app.quit step. It does not
// authorize reading a page, posting input, restoring consent or replaying work.
// Only a prior permanent control approval suspended by machine cleanup qualifies.
func (s *Service) AuthorizeCleanupQuit(ctx context.Context, op Operation) (*Lease, string, error) {
	c, err := s.client(ctx)
	if err != nil {
		return nil, "", err
	}
	ns, err := s.namespace(ctx)
	if err != nil {
		return nil, "", err
	}
	if op.SessionID != c.SessionID || op.Mode != Control || op.Scope != (Scope{Kind: "application", BundleID: "com.google.Chrome"}) {
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
		control := false
		for _, mode := range modes {
			control = control || mode == Control
		}
		if !control || s.policy(ctx, c, r) != nil || s.options.Policy(ctx, c, op.Scope, []Mode{Control}, r.DurationSeconds) != nil {
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
