package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
	"sort"
	"time"
)

// Caller holds b.mu. UNKNOWN is provisional while its original input owns its
// reply. Independent legacy targets remain queryable; a Playwright invocation's
// existing proof instead requires exclusive pending-operation ownership.
func receiptQueryOwnerActiveLocked(c *channel, query Command) bool {
	if c.playwright != nil {
		return true
	}
	for _, pending := range c.pending {
		if (pending.mutation || pending.playwright) && (pending.command.AttemptID == query.AttemptID || sameControlExecutorTarget(pending.command.Identity, query.Identity)) {
			return true
		}
	}
	return false
}

// refreshUnknownReceipts performs bounded original-receipt reads only. It never
// dispatches the original command, emits page values, or proves business success.
func (b *Broker) refreshUnknownReceipts(ctx context.Context, p auth.Principal) {
	actual, err := auth.FromContext(ctx)
	if authorize(ctx, p, false) != nil || err != nil || actual.ClientID != p.ClientID {
		return
	}
	b.mu.Lock()
	ids := []string{}
	for _, c := range b.channels {
		if c.grant.Principal.Namespace != p.Namespace || c.conn == nil || c.fixtureOnly || c.lifecycleInhibited || c.privateInspection != nil || c.privateCredential != nil || c.privateFlow != nil || c.privateAdvance != nil {
			continue
		}
		for id := range c.unknown {
			original, ok := c.attempts[id]
			if ok && original.FingerprintVersion == 2 && original.FingerprintSHA256 != "" && original.BrokerEpoch == b.epoch && original.ChannelEpoch == c.epoch && original.ScopeHash == c.scopeHash {
				if !receiptQueryOwnerActiveLocked(c, original) {
					ids = append(ids, id)
				}
			}
		}
	}
	b.mu.Unlock()
	sort.Strings(ids)
	if len(ids) > 4 {
		ids = ids[:4]
	}
	if len(ids) == 0 {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for _, id := range ids {
		if bounded.Err() != nil {
			return
		}
		_, _ = b.QueryReceipt(bounded, p, id)
	}
}
