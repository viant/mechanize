package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"time"
)

// Closing the owning Runtime session inhibits private/DOM capabilities before
// ordinary Endly teardown. It does not wait behind browser I/O, read the Vault,
// remove durable protection, claim cleanup or replay an uncertain operation.
func (h *Host) cancelOwnedSession(ctx context.Context, p auth.Principal, id string) error {
	actual, e := auth.FromContext(ctx)
	if e != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return auth.ErrUnauthorized
	}
	defer func() {
		if manager := h.nativeControl; manager != nil {
			// The input helper may still be finishing the cancelled session's
			// last bounded action. Queue only this idempotent presentation
			// release; never cancel/replay an action or change its receipts.
			go func() {
				release, cancel := context.WithTimeout(context.WithoutCancel(ctx), 35*time.Second)
				defer cancel()
				_ = manager.ReleasePresentationSession(release, p, id)
			}()
		}
	}()
	defer func() {
		if gateway := h.nativeByUser[p.Namespace]; gateway != nil {
			go func() {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 35*time.Second)
				defer cancel()
				_, _ = gateway.ReleaseControlBadgeSession(cleanup, p, id)
			}()
		}
	}()
	if s := h.credentials; s != nil {
		s.mu.Lock()
		items := []*credentialSession{}
		for _, item := range s.pending {
			if item.actor.Namespace == p.Namespace && item.actor.ClientID == p.ClientID && item.consent.SessionID == id {
				items = append(items, item)
			}
		}
		s.mu.Unlock()
		for _, item := range items {
			if item.cancel != nil {
				item.cancel()
			}
			if exposure := item.exposure.Load(); exposure != nil && exposure.lease != nil {
				exposure.lease.Retire()
			}
		}
		h.retireClosingCredentialSources(ctx, p, id, items)
	}
	return h.cancelWindowFrameSession(ctx, p, id)
}
