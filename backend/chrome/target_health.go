package chrome

// CDP input may complete against a successor document in the same tab. Exact
// document identity remains in ownership/proof records, but hazards occupy the
// physical tab/frame until retirement proves the original input lane drained.
func sameControlExecutorTarget(a, b Identity) bool {
	return a.ProfileChannel == b.ProfileChannel && a.BrowserInstance == b.BrowserInstance && a.TabID == b.TabID && a.FrameID == b.FrameID
}
func knownControlDocument(d Identity) bool {
	return d.ProfileChannel != "" && d.BrowserInstance != "" && d.TabID > 0 && d.FrameID == 0 && d.DocumentID != "" && d.Generation > 0
}
func boundControlDocument(command Command) bool {
	return knownControlDocument(command.Identity) && command.ControlLease != nil && command.ControlLease.ID != "" && command.ControlLease.Generation > 0
}

// Unknowns without an original owned target tuple remain conservative. Audit
// receipts and UNKNOWN records are never removed or resolved by this predicate.
func domUnknownForTargetLocked(c *channel, target Identity) bool {
	return domUnknownForTargetOtherThanLocked(c, target, "")
}
func domUnknownForTargetOtherThanLocked(c *channel, target Identity, own string) bool {
	for id := range c.unknown {
		if id == own {
			continue
		}
		if visibilityUnknownQualifiedLocked(c, c.visibilityUnknown[id]) {
			continue
		}
		command, exists := c.attempts[id]
		if !exists || command.AttemptID != id || !boundControlDocument(command) || sameControlExecutorTarget(command.Identity, target) {
			return true
		}
	}
	return false
}
func pendingForTargetLocked(c *channel, target Identity) bool {
	for _, pending := range c.pending {
		bound := boundControlDocument(pending.command)
		if !pending.mutation && !pending.playwright && knownControlDocument(pending.command.Identity) {
			switch pending.command.Action {
			case "observe", "read", "resolve", "executor.validate", "executor.receipts":
				bound = true
			}
		}
		if !bound || sameControlExecutorTarget(pending.command.Identity, target) {
			return true
		}
	}
	return false
}
