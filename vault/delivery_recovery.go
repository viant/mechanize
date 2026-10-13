package vault

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

var ErrRetiredDeliveryAbsent = errors.New("retired delivery is no longer held")

// RecoverRetired holds exclusive protection throughout trusted metadata-only
// retirement. A new consent session cannot use secrets or revive the old lease.
// The host supplies independent exact process-exit proof and durable retirement;
// protection is released only after both succeed, with no active readers/input.
func (l *DeliveryLease) RecoverRetired(ctx context.Context, verify, retire func(context.Context) error) error {
	p, e := auth.FromContext(ctx)
	if l == nil || l.gate == nil || e != nil || p.Namespace != l.namespace || !p.HasScope("desktop:control") || verify == nil || retire == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	foreignCleanup := p.ClientID != l.clientID && data.CredentialSourceCleanupMatches(ctx, l.namespace, l.clientID, l.binding.SessionID, l.consent.GrantID, l.consent.Purpose, l.binding.Target.Origin, l.binding.Target.Account)
	if p.ClientID != l.clientID && !foreignCleanup {
		return ErrUnavailable
	}
	g := l.gate
	g.mu.Lock()
	if g.delivery == nil {
		g.mu.Unlock()
		return ErrRetiredDeliveryAbsent
	}
	if g.delivery != l || (!l.retired && !foreignCleanup) || l.inFlight != 0 || l.domReaders != 0 || g.entry != nil || g.readers != 0 {
		g.mu.Unlock()
		return ErrDeliveryProtected
	}
	l.retired = true // Atomic inhibition only after exact cleanup proof and idle checks.
	l.inFlight = 1
	g.mu.Unlock()
	successful := false
	defer func() {
		g.mu.Lock()
		l.inFlight = 0
		if successful && g.delivery == l {
			g.delivery = nil
		}
		g.mu.Unlock()
	}()
	if deliveryCall(func() error { return verify(ctx) }) != nil || ctx.Err() != nil {
		return ErrEntryCleanup
	}
	if deliveryCall(func() error { return retire(ctx) }) != nil || ctx.Err() != nil {
		return ErrEntryCleanup
	}
	if deliveryCall(func() error { return verify(ctx) }) != nil || ctx.Err() != nil {
		return ErrEntryCleanup
	}
	successful = true
	return nil
}
