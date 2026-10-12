package host

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
)

type credentialSessionCleanupKey struct{}
type credentialSessionCleanup struct {
	host                                        *Host
	namespace, client, session, purpose, origin string
	active                                      atomic.Bool
}

func (h *Host) checkCredentialSession(ctx context.Context, p auth.Principal, id string) error {
	if err := h.Runtime.CheckSession(ctx, p, id); err == nil {
		return nil
	}
	cleanup, ok := ctx.Value(credentialSessionCleanupKey{}).(*credentialSessionCleanup)
	if !ok || cleanup.host != h || !cleanup.active.Load() || cleanup.namespace != p.Namespace || cleanup.client != p.ClientID || cleanup.session != id {
		return auth.ErrUnauthorized
	}
	return h.Runtime.CheckClosingSession(ctx, p, id)
}
func (h *Host) checkCredentialCleanupOperation(ctx context.Context, p auth.Principal, surface model.Surface, mutation bool, requested consent.Mode) error {
	cleanup, ok := ctx.Value(credentialSessionCleanupKey{}).(*credentialSessionCleanup)
	if !ok {
		return nil
	}
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if !cleanup.active.Load() || cleanup.host != h || cleanup.namespace != p.Namespace || cleanup.client != p.ClientID || !bound || binding.SessionID != cleanup.session || binding.Purpose != cleanup.purpose || surface.Kind != "web" || surface.Origin != cleanup.origin || !mutation || requested != consent.Control {
		return auth.ErrUnauthorized
	}
	return h.Runtime.CheckClosingSession(ctx, p, cleanup.session)
}

// This callback runs only for the authenticated ORIGINAL owner while Close
// retains its identity. It never borrows a successor's identity or grant.
// Absent-source proof changes protection only; tabs and effect history remain.
func (h *Host) retireClosingCredentialSources(ctx context.Context, p auth.Principal, id string, items []*credentialSession) {
	if h.credentials == nil || h.durable == nil || h.Runtime.CheckClosingSession(ctx, p, id) != nil {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, item := range items {
		item.mu.Lock()
		owned := item.actor.Namespace == p.Namespace && item.actor.ClientID == p.ClientID && item.consent.SessionID == id
		held := item.preparation != nil || item.protected != nil || len(item.attempts) != 0
		binding, origin := item.consent, item.target.Origin
		item.mu.Unlock()
		if !owned || !held || bounded.Err() != nil {
			continue
		}
		cleanup := &credentialSessionCleanup{host: h, namespace: p.Namespace, client: p.ClientID, session: id, purpose: binding.Purpose, origin: origin}
		cleanup.active.Store(true)
		original := auth.WithConsentBinding(bounded, binding)
		original = context.WithValue(original, credentialSessionCleanupKey{}, cleanup)
		// Failure retains protection. Session closure still inhibits input; a live
		// source, revoked consent or uncertain proof never becomes automatic success.
		func() {
			defer cleanup.active.Store(false)
			_ = h.credentials.retireAbsentCredentialSources(original, p, origin)
		}()
	}
}
