package chrome

import "encoding/json"

// Called under broker mutex. A retained source blocks its exact tab; active
// private exchanges remain exclusive. This never bypasses ordinary leases,
// process checks, unknown receipts or Host consent/exposure admission.
func scopeDisjointLocked(c *channel, i Identity) bool {
	if i.TabID <= 0 || i.DocumentID == "" || i.ProfileChannel != c.grant.ProfileChannel || i.BrowserInstance != c.grant.BrowserInstance || c.privateCredential != nil || c.privateAdvance != nil || c.privacyPending != nil || c.manualPending != nil {
		return false
	}
	held := false
	for _, source := range []Identity{func() Identity {
		if c.privateInspection != nil {
			return c.privateInspection.identity
		}
		return Identity{}
	}(), func() Identity {
		if c.privateFlow != nil {
			return c.privateFlow.authority.Document.Identity
		}
		return Identity{}
	}(), func() Identity {
		if c.privacy != nil {
			return c.privacy.identity
		}
		return Identity{}
	}()} {
		if source.TabID == 0 {
			continue
		}
		held = true
		if source.TabID == i.TabID {
			return false
		}
	}
	return held
}
func scopedPublicFrameLocked(c *channel, data []byte) bool {
	var frame struct {
		Type      string `json:"type"`
		RequestID string `json:"requestId"`
	}
	if json.Unmarshal(data, &frame) != nil {
		return false
	}
	if p := c.pending[frame.RequestID]; p != nil && (scopeDisjointLocked(c, p.command.Identity) || ownedPublicReadPendingLocked(c, p)) {
		return true
	}
	if c.playwright != nil && (frame.Type == "playwright.result" || frame.Type == "playwright.event") && scopeDisjointLocked(c, c.playwright.command.Identity) {
		return true
	}
	return false
}

func protectedSourceIdentityLocked(c *channel, i Identity) bool {
	for _, source := range c.protectionSources {
		if source.Identity.TabID == i.TabID && source.Identity.DocumentID == i.DocumentID {
			return true
		}
	}
	return false
}
func scopedInventoryFrameLocked(c *channel, data []byte) bool {
	if len(c.protectionSources) == 0 || c.privateCredential != nil || c.privateAdvance != nil || c.privacyPending != nil || c.manualPending != nil {
		return false
	}
	var frame struct{ Type string }
	return json.Unmarshal(data, &frame) == nil && frame.Type == "documents"
}
