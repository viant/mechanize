package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
	"time"
)

// This is the existing held reconnect snapshot's revocation lane, not input
// authority. Only its exact original UNKNOWN tuple may use executor.retire
// before normal executor readiness. The authenticated worker proves full target
// death and an idle input lane; its ACK never resolves the original effect.
func reconnectTargetRetirementLocked(c *channel, command Command) bool {
	x := c.reconnectBindings
	if x == nil || x.conn != c.conn || x.published || !time.Now().Before(x.deadline) || c.playwrightTargetRetirementVersion != 1 || command.Action != "executor.retire" || command.ControlLease == nil || command.Locator != nil || command.Args != nil {
		return false
	}
	original, ok := x.retirements[command.AttemptID]
	return ok && original.Identity == command.Identity && original.ControlLease != nil && *original.ControlLease == *command.ControlLease && command.FingerprintVersion == 2 && command.FingerprintSHA256 == original.FingerprintSHA256
}

// targetRetirementProvenLocked accepts only retained, exact original audit tuples.
// The caller verifies the current authenticated channel process before using it.
func targetRetirementProvenLocked(c *channel, a ControlAuthority) bool {
	if c == nil || c.grant.Principal.Namespace != a.Owner || c.conn == nil || !c.executorQualified || pendingForTargetLocked(c, a.Document.Identity) || domUnknownForTargetLocked(c, a.Document.Identity) {
		return false
	}
	for id, retired := range c.retiredTargets {
		original, exists := c.attempts[id]
		receipt, known := c.receipts[id]
		if !exists || !known || retired.AttemptID != id || original.AttemptID != id || retired.Identity != a.Document.Identity || original.Identity != retired.Identity || retired.ControlLease == nil || original.ControlLease == nil || *retired.ControlLease != a.Lease || *original.ControlLease != a.Lease || retired.BrokerEpoch != a.BrokerEpoch || original.BrokerEpoch != retired.BrokerEpoch || retired.ChannelEpoch != a.ChannelEpoch || original.ChannelEpoch != retired.ChannelEpoch || retired.ScopeHash != a.ScopeHash || original.ScopeHash != retired.ScopeHash || c.scopeHash != a.ScopeHash || retired.FingerprintVersion != 2 || original.FingerprintVersion != 2 || !fingerprintV2Hash.MatchString(retired.FingerprintSHA256) || original.FingerprintSHA256 != retired.FingerprintSHA256 || receipt.AttemptID != id || receipt.Identity != retired.Identity || receipt.ControlLease == nil || *receipt.ControlLease != a.Lease || receipt.FingerprintVersion != 2 || receipt.FingerprintSHA256 != retired.FingerprintSHA256 || receipt.DispatchState != "unknown" || receipt.EffectState != "unknown" {
			continue
		}
		return true
	}
	return false
}

// A reconnect ACK can revoke the original executor hazard even if that helper
// connection has ended. It supplies no replacement authority; normal admission
// below must still authorize and qualify the new document independently.
func (g *Gateway) consumeTargetRetirement(p auth.Principal) {
	g.controlMu.Lock()
	var originals []ControlAuthority
	for _, record := range g.controls {
		if record.authority.Owner == p.Namespace && record.authority.ClientID == p.ClientID {
			originals = append(originals, *record.authority)
		}
	}
	g.controlMu.Unlock()
	for _, original := range originals {
		c := g.controlChannel(original)
		if c == nil {
			continue
		}
		g.broker.mu.Lock()
		retired := targetRetirementProvenLocked(c, original)
		g.broker.mu.Unlock()
		if retired {
			g.controlMu.Lock()
			g.clearControlLocked(original)
			g.controlMu.Unlock()
		}
	}
}

func reconnectRetirementPendingOnlyLocked(c *channel) bool {
	for _, p := range c.pending {
		if p.mutation || p.playwright || !reconnectTargetRetirementLocked(c, p.command) {
			return false
		}
	}
	return true
}

func (b *Broker) retireReconnectTargets(ctx context.Context, c *channel, x *reconnectBindingExchange, rows []ReconnectBinding, check func(context.Context) error) error {
	requested := make(map[string]bool, len(x.targetRetirementAttempts))
	for _, id := range x.targetRetirementAttempts {
		requested[id] = true
	}
	for _, row := range rows {
		if !requested[row.AttemptID] {
			continue
		}
		delete(requested, row.AttemptID)
		if row.DispatchState != "unknown" || row.ControlLease == nil || !fingerprintV2ID.MatchString(row.ControlLease.ID) || row.ControlLease.Generation == 0 || !fingerprintV2Hash.MatchString(row.Fingerprint) || !fingerprintV2ID.MatchString(row.AttemptID) {
			return errReconnectBindings
		}
		original := Command{Identity: row.Identity, AttemptID: row.AttemptID, BrokerEpoch: row.Fence.BrokerEpoch, ChannelEpoch: row.Fence.ChannelEpoch, ScopeHash: row.Fence.ScopeHash, ControlLease: row.ControlLease, FingerprintVersion: 2, FingerprintSHA256: row.Fingerprint}
		b.mu.Lock()
		if c.reconnectBindings != x || c.conn != x.conn {
			b.mu.Unlock()
			return errReconnectBindings
		}
		if x.retirements == nil {
			x.retirements = map[string]Command{}
		}
		x.retirements[row.AttemptID] = original
		// A restarted broker must arm the original hazard before requesting
		// proof. Loss/refusal of the ACK retains UNKNOWN and inhibits readiness.
		// This is only an immutable identity tuple, not a reconstructed action.
		if _, exists := c.attempts[row.AttemptID]; !exists {
			c.attempts[row.AttemptID] = original
		}
		if _, exists := c.receipts[row.AttemptID]; !exists {
			c.receipts[row.AttemptID] = Reply{Identity: row.Identity, AttemptID: row.AttemptID, ControlLease: row.ControlLease, FingerprintVersion: 2, FingerprintSHA256: row.Fingerprint, DispatchState: "unknown", EffectState: "unknown", Error: browserError("unknownEffect", "Original mutation remains uncertain and cannot be replayed", "unknown")}
		}
		c.unknown[row.AttemptID] = true
		b.mu.Unlock()
		command := original
		command.Action = "executor.retire"
		reply, err := b.call(ctx, c, command, false, func() error { return check(ctx) })
		b.mu.Lock()
		delete(x.retirements, row.AttemptID)
		valid := err == nil && c.conn == x.conn && c.reconnectBindings == x && reply.Error == nil && reply.Identity == row.Identity && reply.AttemptID == row.AttemptID && reply.ControlLease != nil && *reply.ControlLease == *row.ControlLease && reply.FingerprintVersion == 2 && reply.FingerprintSHA256 == row.Fingerprint && reply.RetiredAuthorityQuiesced && reply.DispatchState == "unknown" && reply.EffectState == "unknown"
		if valid {
			if c.retiredTargets == nil {
				c.retiredTargets = map[string]Command{}
			}
			c.retiredTargets[row.AttemptID] = original
			delete(c.unknown, row.AttemptID)
		}
		b.mu.Unlock()
		if !valid {
			return errReconnectBindings
		}
	}
	if len(requested) != 0 {
		return errReconnectBindings
	}
	b.mu.Lock()
	idle := len(c.unknown) == 0
	b.mu.Unlock()
	if !idle {
		return errReconnectBindings
	}
	return check(ctx)
}
