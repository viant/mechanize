package consent

import (
	"context"
	"errors"
)

func coversModes(available, required []Mode) bool {
	for _, want := range required {
		found := false
		for _, have := range available {
			found = found || have == want
		}
		if !found {
			return false
		}
	}
	return len(required) > 0
}

// RequestOrReuse never approves access. It returns sufficient existing human
// trust or the same still-pending request before creating another prompt.
func (s *Service) RequestOrReuse(ctx context.Context, sessionID string, in RequestInput) (Request, error) {
	c, err := s.client(ctx)
	if err != nil {
		return Request{}, err
	}
	if sessionID != c.SessionID {
		return Request{}, errors.New("authenticated session mismatch")
	}
	if err = validateInput(in, s.options.MaxDuration); err != nil {
		return Request{}, err
	}
	if err = s.options.Policy(ctx, c, in.Scope, in.Modes, in.DurationSeconds); err != nil {
		return Request{}, err
	}
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	if err = ctx.Err(); err != nil {
		return Request{}, err
	}
	mode := in.Modes[0]
	for _, m := range in.Modes {
		if m == Control {
			mode = Control
		}
	}
	g, err := s.findPermanentGrant(ctx, Operation{SessionID: sessionID, Scope: in.Scope, Mode: mode, Purpose: in.Purpose}, in.Modes)
	if err != nil {
		return Request{}, err
	}
	if g != nil {
		if g.State != "active" || g.RevocationState != "" {
			return Request{}, ErrCleanupUnconfirmed
		}
		return Request{ID: g.RequestID, ExistingGrant: g}, nil
	}
	ns, err := s.namespace(ctx)
	if err != nil {
		return Request{}, err
	}
	rows, err := s.read(ctx, "consentrequests", "*", c.ID)
	if err != nil {
		return Request{}, err
	}
	now := int(s.options.Now().UnixMilli())
	for _, r := range rows {
		if r.Namespace != ns || r.ClientID != c.ID || r.SessionID != sessionID || r.policyManaged || r.Purpose != in.Purpose {
			continue
		}
		scope, modes, err := r.details()
		if err != nil {
			return Request{}, err
		}
		if r.Decision == string(AllowSession) && r.GrantState == "active" && r.GrantExpiresAt > now && scope.Covers(in.Scope) && coversModes(modes, in.Modes) {
			if err := s.policy(ctx, c, r); err != nil {
				continue
			}
			if r.RevocationState == string(CleanupUnknown) {
				return Request{}, ErrCleanupUnconfirmed
			}
			s.mu.Lock()
			blocked := s.blocked[ns+":"+r.GrantID]
			s.mu.Unlock()
			if !blocked && r.RevocationState == "" {
				grant, err := r.grant(s.options.Now())
				if err != nil {
					return Request{}, err
				}
				return Request{ID: r.ID, ExistingGrant: &grant}, nil
			}
		}
		if r.RequestState != "pending" || r.Decision != "" || r.RequestExpiresAt <= now || r.DurationSeconds != in.DurationSeconds {
			continue
		}
		// DisplayName is presentation only; compare the actual authority scope.
		if scope.Covers(in.Scope) && in.Scope.Covers(scope) && len(modes) == len(in.Modes) && coversModes(modes, in.Modes) {
			return r.request()
		}
	}
	return s.createRequest(ctx, c, sessionID, in, c.ID)
}
