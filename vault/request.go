package vault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"github.com/viant/mechanize/auth"
	"sync"
	"time"
)

// Binding is private backend evidence, not an agent-provided assertion. All
// fields must match a fresh observation immediately before credential entry.
type Binding struct {
	SessionID, DocumentID, NavigationID string
	Target                              Target
}

func (b Binding) valid() bool {
	return b.SessionID != "" && b.DocumentID != "" && b.NavigationID != "" && b.Target.Validate() == nil
}

type Request struct {
	ID        string
	Target    Target
	ExpiresAt time.Time
}
type pending struct {
	namespace string
	binding   Binding
	request   Request
}

// Hooks are trusted local host adapters. Present must route to the signed native
// secure-input UI, and Fresh must inspect actual browser state. A dropped or
// changed document fails closed; Resume owns normal Endly continuation.
type Hooks struct {
	Present func(context.Context, Request) error
	Fresh   func(context.Context, Binding) (Binding, error)
	Resume  func(context.Context, Binding, Reference) error
}
type Manager struct {
	store   *Store
	legacy  *LegacyResolver
	hooks   Hooks
	mu      sync.Mutex
	pending map[string]pending
}

// NewManagerWithLegacy explicitly opts a trusted legacy enrollment map into
// reuse. It does not import files or add any default-key fallback.
func NewManagerWithLegacy(store *Store, hooks Hooks, legacy *LegacyResolver) (*Manager, error) {
	m, err := NewManager(store, hooks)
	if err != nil {
		return nil, err
	}
	m.legacy = legacy
	return m, nil
}

func NewManager(store *Store, hooks Hooks) (*Manager, error) {
	if store == nil || hooks.Present == nil || hooks.Fresh == nil || hooks.Resume == nil {
		return nil, ErrUnavailable
	}
	return &Manager{store: store, hooks: hooks, pending: map[string]pending{}}, nil
}
func (m *Manager) fresh(ctx context.Context, b Binding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	actual, err := m.hooks.Fresh(ctx, b)
	if err != nil || actual != b || !actual.valid() {
		return ErrStale
	}
	return nil
}

// Ensure is a local workflow pause contract. Its public successful value is only
// a resource URL. A miss presents native UI automatically and returns ErrPending;
// the local request ID is never needed in the DSL or an MCP result.
func (m *Manager) Ensure(ctx context.Context, b Binding) (Reference, error) {
	p, err := auth.FromContext(ctx)
	if err != nil {
		return Reference{}, err
	}
	if !b.valid() {
		return Reference{}, ErrScope
	}
	if err = m.fresh(ctx, b); err != nil {
		return Reference{}, err
	}
	ref, err := m.store.Lookup(ctx, b.Target)
	if err == nil {
		return ref, nil
	}
	if err != ErrMissing {
		return Reference{}, err
	}
	if m.legacy != nil {
		legacyRef, legacyErr := m.legacy.Reference(ctx, b.Target)
		if legacyErr == nil {
			if err = m.legacy.Consume(ctx, b.Target, legacyRef, func(Credentials) error { return nil }); err != nil {
				return Reference{}, err
			}
			return legacyRef, nil
		}
		if legacyErr != ErrMissing {
			return Reference{}, legacyErr
		}
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return Reference{}, ErrUnavailable
	}
	r := Request{ID: hex.EncodeToString(random[:]), Target: b.Target, ExpiresAt: time.Now().Add(5 * time.Minute)}
	m.mu.Lock()
	for id, item := range m.pending {
		if time.Now().After(item.request.ExpiresAt) {
			delete(m.pending, id)
		} else if item.namespace == p.Namespace && item.binding == b {
			m.mu.Unlock()
			return Reference{}, ErrPending
		}
	}
	if len(m.pending) >= 128 {
		m.mu.Unlock()
		return Reference{}, ErrUnavailable
	}
	m.pending[r.ID] = pending{namespace: p.Namespace, binding: b, request: r}
	m.mu.Unlock()
	if err = m.hooks.Present(ctx, r); err != nil {
		m.mu.Lock()
		delete(m.pending, r.ID)
		m.mu.Unlock()
		return Reference{}, ErrUnavailable
	}
	return Reference{}, ErrPending
}

// Submit belongs exclusively to the verified native-human local transport, never
// MCP. Buffers are cleared even on refusal. Each request has one submission;
// cancellation/uncertain resume cannot replay credentials into a new document.
func (m *Manager) Submit(ctx context.Context, id string, username, password []byte) error {
	defer clear(username)
	defer clear(password)
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	p, _ := auth.FromContext(ctx)
	m.mu.Lock()
	item, ok := m.pending[id]
	if !ok || item.namespace != p.Namespace {
		m.mu.Unlock()
		return ErrStale
	}
	delete(m.pending, id)
	m.mu.Unlock()
	if time.Now().After(item.request.ExpiresAt) {
		return ErrStale
	}
	if err := m.fresh(ctx, item.binding); err != nil {
		return err
	}
	ref, err := m.store.put(ctx, item.binding.Target, username, password)
	if err != nil {
		return err
	}
	if err = m.fresh(ctx, item.binding); err != nil {
		return err
	}
	if err = m.hooks.Resume(ctx, item.binding, ref); err != nil {
		return ErrUnavailable
	}
	return nil
}
func (m *Manager) Cancel(ctx context.Context, id string) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	p, _ := auth.FromContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.pending[id]
	if !ok || item.namespace != p.Namespace {
		return ErrStale
	}
	delete(m.pending, id)
	return nil
}

// Consume checks navigation again at the last local credential boundary. Browser
// adapters must verify frame/form origin and suppress recording/capture before
// synchronously applying bytes; this contract alone does not prove that adapter.
func (m *Manager) Consume(ctx context.Context, b Binding, ref Reference, consume func(Credentials) error) error {
	if !b.valid() {
		return ErrScope
	}
	if err := m.fresh(ctx, b); err != nil {
		return err
	}
	err := m.store.Consume(ctx, b.Target, ref, consume)
	if err == ErrMissing && m.legacy != nil {
		return m.legacy.Consume(ctx, b.Target, ref, consume)
	}
	return err
}
