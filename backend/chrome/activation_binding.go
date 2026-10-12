package chrome

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/viant/mechanize/auth"
)

// ActivationBinding is produced only from the current signed native peer and
// the sealed browser admission. Host persistence adds immutable durable intent
// identity. It is metadata, not a renderer/input lease or reconciliation proof.
type ActivationBinding struct {
	Namespace, ClientID, ProfileChannel, BrowserInstance           string
	Origin, BrowserAttemptID, BrokerEpoch, ChannelEpoch, ScopeHash string
	ChromeStartToken, NativeHostStartToken, FingerprintSHA256      string
	TabID, ChromePID, NativeHostPID, FingerprintVersion            int
}

func (a *openOriginAdmission) activationBinding(ctx context.Context, p auth.Principal, attempt string) (ActivationBinding, error) {
	if a == nil || a.action != "browser.activateTab" || ctx.Err() != nil || a.evidence == nil || a.evidence.ChromeParent.PID <= 0 || a.evidence.ChromeParent.StartToken == "" || a.evidence.NativeHost.PID <= 0 || a.evidence.NativeHost.StartToken == "" || !fingerprintV2Hash.MatchString(attempt) {
		return ActivationBinding{}, auth.ErrUnauthorized
	}
	b, c := a.gateway.broker, a.channel
	b.mu.Lock()
	current := !b.closed && c.conn == a.conn && c.processEvidence == a.evidence && b.epoch == a.brokerEpoch && c.epoch == a.channelEpoch && c.scopeHash == a.scopeHash && channelScopeQualified(c) && a.principal.Namespace == p.Namespace && a.principal.ClientID == p.ClientID
	b.mu.Unlock()
	if !current {
		return ActivationBinding{}, auth.ErrUnauthorized
	}
	v := ActivationBinding{Namespace: p.Namespace, ClientID: p.ClientID, ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, Origin: a.origin, TabID: a.tabID, BrowserAttemptID: attempt, BrokerEpoch: a.brokerEpoch, ChannelEpoch: a.channelEpoch, ScopeHash: a.scopeHash, ChromePID: a.evidence.ChromeParent.PID, ChromeStartToken: a.evidence.ChromeParent.StartToken, NativeHostPID: a.evidence.NativeHost.PID, NativeHostStartToken: a.evidence.NativeHost.StartToken, FingerprintVersion: 1}
	// Exact extension activation fingerprint, including original transport fences.
	canonical, e := json.Marshal([]any{"mechanize-browser-activate-tab-v1", v.ProfileChannel, v.BrowserInstance, v.BrowserAttemptID, v.Origin, v.TabID, v.BrokerEpoch, v.ChannelEpoch, v.ScopeHash})
	if e != nil {
		return ActivationBinding{}, e
	}
	digest := sha256.Sum256(canonical)
	v.FingerprintSHA256 = hex.EncodeToString(digest[:])
	return v, nil
}
