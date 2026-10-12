package host

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
)

func (b *ConsentBroker) controllerPolicyContext(ctx context.Context, p auth.Principal) (context.Context, func(), error) {
	if !strings.HasPrefix(p.ClientID, "controller:") {
		return ctx, func() {}, nil
	}
	if b.options.ControllerPolicy == nil {
		return nil, nil, auth.ErrUnauthorized
	}
	bound, expires, release, err := b.options.ControllerPolicy(ctx, p)
	if err == nil && (bound == nil || release == nil || bound.Err() != nil || !expires.After(time.Now())) {
		if release != nil {
			release()
		}
		return nil, nil, auth.ErrUnauthorized
	}
	return bound, release, err
}

func (b *ConsentBroker) ResolveControllerPolicyGrant(ctx context.Context, p auth.Principal, op consent.Operation) (*consent.Grant, error) {
	if !strings.HasPrefix(p.ClientID, "controller:") {
		return nil, nil
	}
	if b.options.ControllerPolicy == nil {
		return nil, auth.ErrUnauthorized
	}
	bound, expires, release, err := b.options.ControllerPolicy(ctx, p)
	if err != nil {
		if release != nil {
			release()
		}
		return nil, err
	}
	if bound == nil || release == nil || bound.Err() != nil || !expires.After(time.Now()) {
		if release != nil {
			release()
		}
		return nil, auth.ErrUnauthorized
	}
	defer release()
	bound, service, err := b.bound(bound, p)
	if err != nil {
		return nil, err
	}
	select {
	case b.policyLane <- struct{}{}:
		defer func() { <-b.policyLane }()
	case <-bound.Done():
		return nil, bound.Err()
	}
	modes := []consent.Mode{op.Mode}
	// A normal observe/control grant keeps the same binding through private
	// prepare, promoted reads and later inputs; each operation still checks its
	// exact current mode ceiling. Recording is never added implicitly.
	if (op.Mode == consent.Observe || op.Mode == consent.Control) && p.HasScope("desktop:control") && b.options.Policy(bound, p, op.Scope, []consent.Mode{consent.Observe, consent.Control}, 1) == nil {
		modes = []consent.Mode{consent.Observe, consent.Control}
	}
	raw, _ := json.Marshal([]any{p.Namespace, p.ClientID, op.SessionID, op.Scope, modes, op.Purpose})
	key := string(raw)
	for k, g := range b.policyGrants {
		if !g.ExpiresAt.After(time.Now()) {
			delete(b.policyGrants, k)
		}
	}
	if grant := b.policyGrants[key]; grant != nil {
		return grant, nil
	}
	// Capacity is a refusal, never an eviction of live authorization or effects.
	if len(b.policyGrants) >= 1024 {
		return nil, auth.ErrUnauthorized
	}
	seconds := int(time.Until(expires) / time.Second)
	if seconds > 900 {
		seconds = 900
	}
	if seconds < 1 {
		return nil, auth.ErrUnauthorized
	}
	grant, err := service.CreatePolicyGrant(bound, op.SessionID, consent.RequestInput{Scope: op.Scope, Modes: modes, Purpose: op.Purpose, DurationSeconds: seconds})
	if err != nil {
		return nil, err
	}
	b.policyGrants[key] = grant
	return grant, nil
}

func (h *Host) controllerPolicyAuthorization(ctx context.Context, p auth.Principal) (context.Context, time.Time, func(), error) {
	if h.chrome == nil {
		return nil, time.Time{}, nil, auth.ErrUnauthorized
	}
	authorization, err := h.chrome.AuthorizeControllerPolicy(ctx, p)
	if err != nil {
		return nil, time.Time{}, nil, err
	}
	return authorization.Context, authorization.ExpiresAt, authorization.Release, nil
}
