package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
	"sort"
	"time"
)

// TabHandleInventory intentionally excludes page titles and document contents.
// Handles identify an enrolled browser/profile/tab, never an authorization grant.
type TabHandle struct {
	Handle string `json:"handle"`
	Origin string `json:"origin"`
}
type TabHandleInventory struct {
	Tabs       []TabHandle `json:"tabs"`
	Complete   bool        `json:"complete"`
	ObservedAt time.Time   `json:"observedAt"`
	Reason     string      `json:"reason,omitempty"`
}

// ListTabHandles observes fresh origin-scoped browser metadata, independently
// of renderer readiness and historical reconnect records. Handles are routing
// observations only; private protections and uncertain attempts remain intact.
func (g *Gateway) ListTabHandles(ctx context.Context, p auth.Principal, origin string) (TabHandleInventory, error) {
	out := TabHandleInventory{Tabs: []TabHandle{}, Complete: false, Reason: "none"}
	if err := authorize(ctx, p, false); err != nil {
		return out, err
	}
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != p.ClientID || !OrdinaryWebsiteOrigin(origin) {
		return out, auth.ErrUnauthorized
	}
	out.Complete = true
	if g == nil || g.broker == nil {
		out.Complete = false
		out.Reason = "noQualifiedChannel"
		return out, nil
	}
	bounded, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	b := g.broker
	b.mu.Lock()
	keys := []string{}
	for key, c := range b.channels {
		if c.grant.Principal.Namespace == p.Namespace && allowedOrigin(c.grant, origin) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	selected := make([]*channel, 0, len(keys))
	for _, key := range keys {
		selected = append(selected, b.channels[key])
	}
	b.mu.Unlock()
	if len(selected) == 0 {
		out.Complete = false
		out.Reason = "noQualifiedChannel"
	}
	for _, c := range selected {
		reply, reason := b.currentTabInventory(bounded, c, p.Namespace, origin)
		if reason != "none" {
			out.Complete = false
			if out.Reason == "none" {
				out.Reason = reason
			}
		}
		if reason != "none" && reason != "inventoryLimit" {
			continue
		}
		observed := time.Now().UTC()
		if out.ObservedAt.IsZero() {
			out.ObservedAt = observed
		}
		for _, id := range reply.TabIDs {
			if len(out.Tabs) >= maximumTabInventory {
				out.Complete = false
				out.Reason = "inventoryLimit"
				break
			}
			handle := (Document{Identity: Identity{ProfileChannel: reply.profileChannel, BrowserInstance: reply.browserInstance, TabID: id}}).QualifiedTabID()
			out.Tabs = append(out.Tabs, TabHandle{Handle: handle, Origin: origin})
		}
	}
	return out, ctx.Err()
}
