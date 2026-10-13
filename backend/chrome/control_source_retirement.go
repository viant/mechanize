package chrome

// knownPressSourceRetirementLocked authorizes only requesting revocation of an
// existing lease. The worker must independently prove source absence and ACK
// that exact lease; a known dispatch receipt does not itself prove retirement.
// The caller holds the broker mutex. Logical arguments are deliberately absent
// from retained v2 commands, so this compares their committed fingerprint.
func knownPressSourceRetirementLocked(c *channel, identity Identity, lease *Lease, brokerEpoch string) bool {
	if lease == nil || domUnknownForTargetLocked(c, identity) {
		return false
	}
	for _, document := range c.documents {
		if document.TabID == identity.TabID && document.FrameID == identity.FrameID && document.DocumentID == identity.DocumentID {
			return false
		}
	}
	for id, command := range c.attempts {
		if command.Action != "element.press" || command.Identity != identity || command.ControlLease == nil || *command.ControlLease != *lease || command.FingerprintVersion != 2 || !fingerprintV2Hash.MatchString(command.FingerprintSHA256) || command.AttemptID != id || command.BrokerEpoch != brokerEpoch || command.ChannelEpoch != c.epoch || command.ScopeHash != c.scopeHash {
			continue
		}
		receipt, ok := c.receipts[id]
		if ok && receipt.Error == nil && receipt.AttemptID == id && receipt.Identity == identity && receipt.ControlLease != nil && *receipt.ControlLease == *lease && receipt.FingerprintVersion == 2 && receipt.FingerprintSHA256 == command.FingerprintSHA256 && receipt.DispatchState == "dispatched" && (receipt.EffectState == "unverified" || receipt.EffectState == "verified") {
			return true
		}
	}
	return false
}
