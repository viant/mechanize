package consent

import (
	"context"
	"sync"
)

// Eligibility is deliberately application-only. Native input into Chrome could
// interact with unreconciled browser work; no browser/desktop/recording authority
// is inferred from native physical cleanup or a fresh empty browser registry.
func (s *Service) nativeCleanupEligible(op Operation) bool {
	return s.options.RecoverNativeCleanup != nil && op.Mode == Control && op.Scope.Kind == "application" && op.Scope.BundleID != "com.google.Chrome" && op.Scope.Validate() == nil
}

// This issues a scoped lease against retained human authority, without clearing
// its durable CleanupUnknown state. Every new operation needs independent native
// proof; uncertain business outcomes remain barriers in their original runs.
func (s *Service) authorizeCleanupNative(ctx context.Context, op Operation) (*Lease, error) {
	c, err := s.client(ctx)
	if err != nil {
		return nil, err
	}
	ns, err := s.namespace(ctx)
	if err != nil {
		return nil, err
	}
	if !s.nativeCleanupEligible(op) || op.SessionID != c.SessionID || op.GrantID == "" || op.Purpose == "" {
		return nil, ErrCleanupUnconfirmed
	}
	read := func() (record, error) {
		rows, err := s.read(ctx, "consenttrusted", "*", c.ID)
		if err != nil {
			return record{}, err
		}
		for _, r := range rows {
			if r.Namespace == ns && r.ClientID == c.ID && r.GrantID == op.GrantID && r.permanent() && r.cleanupMachineOnly && r.GrantState == "active" && r.RevocationState == string(CleanupUnknown) {
				return r, nil
			}
		}
		return record{}, ErrCleanupUnconfirmed
	}
	r, err := read()
	if err != nil {
		return nil, err
	}
	policy := func() error {
		scope, modes, e := r.details()
		if e != nil || !scope.Covers(op.Scope) {
			return ErrCleanupUnconfirmed
		}
		control := false
		for _, mode := range modes {
			control = control || mode == Control
		}
		if !control {
			return ErrCleanupUnconfirmed
		}
		if e = s.policy(ctx, c, r); e != nil {
			return e
		}
		return s.options.Policy(ctx, c, op.Scope, []Mode{Control}, r.DurationSeconds)
	}
	if err = policy(); err != nil {
		return nil, err
	}
	key := ns + ":" + r.GrantID
	s.mu.Lock()
	blocked := s.humanBlocked[key] || len(s.active[key]) != 0
	s.mu.Unlock()
	if blocked {
		return nil, ErrCleanupUnconfirmed
	}
	if err = s.options.RecoverNativeCleanup(ctx, c, op.Scope); err != nil {
		return nil, ErrCleanupUnconfirmed
	}
	// Re-read immutable audit-derived revocation provenance after the proof. A
	// concurrent human stop must not be overwritten or mistaken for machine cleanup.
	after, err := read()
	if err != nil || after.Revision != r.Revision || after.ScopeJSON != r.ScopeJSON || after.ModesJSON != r.ModesJSON {
		return nil, ErrCleanupUnconfirmed
	}
	if err = policy(); err != nil {
		return nil, err
	}
	token, err := randomID()
	if err != nil {
		return nil, err
	}
	owned, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	if s.humanBlocked[key] || len(s.active[key]) != 0 || ctx.Err() != nil {
		s.mu.Unlock()
		cancel()
		return nil, ErrCleanupUnconfirmed
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
	return &Lease{Context: owned, Release: release}, nil
}
