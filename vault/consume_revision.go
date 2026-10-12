package vault

import (
	"context"
	"github.com/viant/mechanize/auth"
)

// ConsumeRevision binds native selection to exactly the authenticated ciphertext
// selected. Only the local callback receives values. No legacy or latest-version
// fallback is permitted. Host consent and exposure protection remain mandatory.
func (s *Store) ConsumeRevision(ctx context.Context, target Target, ref Reference, revision string, consume func(Credentials) error) error {
	p, err := auth.FromContext(ctx)
	if err != nil {
		return err
	}
	if target.Validate() != nil || ref.ResourceURL != reference(p.Namespace, target) || !nativeRevision(revision) || consume == nil {
		return ErrScope
	}
	return s.writeLock(ctx, func() error {
		c, err := s.readRevision(ctx, target, revision)
		if err != nil {
			return err
		}
		defer clear(c.username)
		defer clear(c.password)
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		return deliveryCall(func() error { return consume(c) })
	})
}

// ConsumeRevision preserves Manager's fresh exact document check without
// weakening the selected ciphertext revision into a mutable lookup.
func (m *Manager) ConsumeRevision(ctx context.Context, b Binding, ref Reference, revision string, consume func(Credentials) error) error {
	if m == nil || !b.valid() {
		return ErrScope
	}
	if err := m.fresh(ctx, b); err != nil {
		return err
	}
	if m.privateConsume != nil {
		return m.privateConsume(ctx, b, ref, revision, consume)
	}
	if m.store == nil {
		return ErrUnavailable
	}
	return m.store.ConsumeRevision(ctx, b.Target, ref, revision, consume)
}
