package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
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
}

// ListTabHandles revalidates running peers before exposing origin-scoped handles.
// Retained private scopes do not hide title-free origin/handle metadata.
// Unqualified channels never contribute stale cached routing data.
func (g *Gateway) ListTabHandles(ctx context.Context, p auth.Principal, origin string) (TabHandleInventory, error) {
	out := TabHandleInventory{Tabs: []TabHandle{}, Complete: true}
	if err := authorize(ctx, p, false); err != nil {
		return out, err
	}
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != p.ClientID || !OrdinaryWebsiteOrigin(origin) {
		return out, auth.ErrUnauthorized
	}
	b := g.broker
	b.mu.Lock()
	selected := []*channel{}
	for _, c := range b.channels {
		if c.grant.Principal.Namespace == p.Namespace && allowedOrigin(c.grant, origin) {
			selected = append(selected, c)
		}
	}
	b.mu.Unlock()
	if len(selected) == 0 {
		out.Complete = false
	}
	for _, c := range selected {
		b.mu.Lock()
		conn, epoch := c.conn, c.epoch
		eligible := conn != nil && !c.fixtureOnly && channelScopeQualified(c) && c.executorQualified && c.inventoryComplete && !c.lifecycleInhibited
		b.mu.Unlock()
		if !eligible || b.checkChannelProcess(ctx, c, false) != nil {
			out.Complete = false
			continue
		}
		b.mu.Lock()
		current := c.conn == conn && c.epoch == epoch && channelScopeQualified(c) && c.executorQualified && c.inventoryComplete && !c.lifecycleInhibited
		if !current {
			out.Complete = false
			b.mu.Unlock()
			continue
		}
		if out.ObservedAt.IsZero() || c.inventoryAt.Before(out.ObservedAt) {
			out.ObservedAt = c.inventoryAt
		}
		for _, doc := range c.documents {
			if doc.FrameID == 0 && doc.Origin == origin {
				out.Tabs = append(out.Tabs, TabHandle{Handle: doc.QualifiedTabID(), Origin: origin})
			}
		}
		b.mu.Unlock()
	}
	return out, ctx.Err()
}
