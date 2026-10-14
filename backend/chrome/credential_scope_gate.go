package chrome

import (
	"bytes"
	"encoding/json"
)

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
	if p := c.pending[frame.RequestID]; p != nil && (scopeDisjointLocked(c, p.command.Identity) || ownedPublicReadPendingLocked(c, p) || inactivePrivacyReplacementLocked(c) && reconnectTargetRetirementLocked(c, p.command)) {
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

// Inactive privacy still quarantines DOM output, but it must not poison the
// authenticated transport's setup/attention lane. Existing handlers validate
// challenges, lifecycle, unknown receipts and closed diagnostic fields below.
func inactivePrivacyControlPlaneFrameLocked(c *channel, raw []byte) bool {
	if c == nil || !inactivePrivacyReplacementLocked(c) || len(raw) > MaxFrameBytes {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	var kind string
	if json.Unmarshal(fields["type"], &kind) != nil {
		return false
	}
	allowed := map[string]bool{"type": true}
	switch kind {
	case "executorPrepared":
		allowed["executorChallenge"] = true
		allowed["mutationFingerprintVersion"] = true
	case "documents":
		allowed["documents"] = true
		allowed["credentialCandidates"] = true
		allowed["truncated"] = true
		allowed["capabilities"] = true
		allowed["inputSemantics"] = true
		allowed["unsupported"] = true
		for key, rawRows := range map[string]json.RawMessage{"documents": fields["documents"], "credentialCandidates": fields["credentialCandidates"]} {
			if rawRows == nil {
				continue
			}
			decoder := json.NewDecoder(bytes.NewReader(rawRows))
			decoder.DisallowUnknownFields()
			if key == "documents" {
				var rows []Document
				if decoder.Decode(&rows) != nil || len(rows) > 200 {
					return false
				}
			} else {
				var rows []credentialCandidate
				if decoder.Decode(&rows) != nil || len(rows) > 200 {
					return false
				}
			}
		}
	case "attention":
		allowed["error"] = true
		allowed["reconnect"] = true
	default:
		return false
	}
	for key := range fields {
		if !allowed[key] {
			return false
		}
	}
	return true
}

// Replacement setup retires only original authority; it never reads private DOM.
func inactivePrivacyReplacementLocked(c *channel) bool {
	return c.privacy != nil && !c.privacy.active && c.privacy.conn != c.conn && c.privateFlow == nil && c.privateCredential == nil && c.privateInspection == nil && c.privateAdvance == nil && c.privacyPending == nil && c.manualPending == nil
}
