package consent

import (
	"context"
	"fmt"
)

// RecoverDispatchCleanup retains an existing human approval after independent
// host lifecycle recovery. It neither grants new access nor resolves/replays
// uncertain business effects. Human revocation is rejected by the mutation's
// immutable audit-history check and CAS, including a concurrent human stop.
func (s *Service) RecoverDispatchCleanup(ctx context.Context, grantID string) error {
	c, err := s.client(ctx)
	if err != nil {
		return err
	}
	ns, err := s.namespace(ctx)
	if err != nil {
		return err
	}
	if s.options.RecoverCleanup == nil {
		return ErrCleanupUnconfirmed
	}
	rows, err := s.read(ctx, "consenttrusted", "*", c.ID)
	if err != nil {
		return err
	}
	var r record
	for _, candidate := range rows {
		if candidate.GrantID == grantID {
			r = candidate
			break
		}
	}
	if r.Namespace != ns || r.ClientID != c.ID || r.GrantID != grantID || !r.permanent() || r.GrantState != "active" || r.RevocationState != string(CleanupUnknown) {
		return fmt.Errorf("existing own suspended permanent approval required")
	}
	if !r.cleanupMachineOnly {
		return fmt.Errorf("human revocation or missing cleanup history prevents recovery")
	}
	if err = s.policy(ctx, c, r); err != nil {
		return err
	}
	scope, _, err := r.details()
	if err != nil {
		return err
	}
	key := ns + ":" + grantID
	s.mu.Lock()
	active := len(s.active[key])
	inhibited := s.blocked[key]
	s.mu.Unlock()
	if active != 0 || inhibited {
		return ErrCleanupUnconfirmed
	}
	if err = s.options.RecoverCleanup(ctx, c, scope); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	previous := r
	r.RevocationState = ""
	r.Revision++
	if err = s.write(ctx, "cleanupRecovery", c.ID, r, &previous, true); err != nil {
		return err
	}
	s.mu.Lock()
	// Never erase a concurrent human inhibit. Recovery runs only after the old
	// registry stopped; Authorize independently rechecks both ledger and inhibit.
	s.known[key] = true
	s.mu.Unlock()
	return nil
}
