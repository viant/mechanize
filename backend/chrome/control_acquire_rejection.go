package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"io"
	"net"
)

// A stale-generation rejection is emitted before executor.acquire installs a
// lease. Only the exact closed reply on the pending authenticated request can
// establish this fact. It is not inferred from an arbitrary error string.
func acquireNotInstalled(raw []byte, command Command) bool {
	if command.Action != "executor.acquire" || command.ControlLease == nil || command.AttemptID != "" || len(raw) > 4096 || !uniqueCredentialJSON(raw) {
		return false
	}
	var fields, identityFields, errorFields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 3 || json.Unmarshal(fields["identity"], &identityFields) != nil || len(identityFields) != 6 || json.Unmarshal(fields["error"], &errorFields) != nil || len(errorFields) != 5 {
		return false
	}
	for _, k := range []string{"profileChannel", "browserInstance", "tabId", "frameId", "documentId", "documentGeneration"} {
		if v, ok := identityFields[k]; !ok || bytes.Equal(v, []byte("null")) {
			return false
		}
	}
	for _, k := range []string{"code", "message", "stage", "dispatchState", "effectState"} {
		if v, ok := errorFields[k]; !ok || bytes.Equal(v, []byte("null")) {
			return false
		}
	}
	var r struct {
		RequestID string   `json:"requestId"`
		Identity  Identity `json:"identity"`
		Error     struct {
			Code          string `json:"code"`
			Message       string `json:"message"`
			Stage         string `json:"stage"`
			DispatchState string `json:"dispatchState"`
			EffectState   string `json:"effectState"`
		} `json:"error"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
		return false
	}
	expected := command.Identity
	expected.Generation = r.Identity.Generation
	return r.RequestID == command.RequestID && r.Identity == expected && r.Identity.Generation > command.Identity.Generation && r.Identity.Generation <= 9007199254740991 && r.Error.Code == "staleGeneration" && r.Error.Stage == "browser" && r.Error.DispatchState == "notDispatched" && r.Error.EffectState == "none" && len(r.Error.Message) <= 512
}
func sameAdmissionTarget(previous, next ControlAuthority) bool {
	if next.Document.Generation < previous.Document.Generation {
		return false
	}
	previous.Lease = Lease{}
	next.Lease = Lease{}
	previous.Document.Generation = next.Document.Generation
	return sameControl(previous, next)
}

// Roll back only this new, never-installed reservation. Prior leases, receipts,
// unknown attempts, privacy state and lifecycle inhibition are never cleared.
func (g *Gateway) releaseRejectedAcquisition(ctx context.Context, p auth.Principal, a ControlAuthority, c *channel, conn net.Conn, reply Reply) bool {
	if !reply.acquireNotInstalled || g.broker.verifyChannelProcess(ctx, c) != nil || g.controlCheck(ctx, p, a, c, true) != nil {
		return false
	}
	g.controlMu.Lock()
	defer g.controlMu.Unlock()
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if g.control == nil || g.controlRetiring || !sameControl(*g.control, a) || c.conn != conn || c.processEvidence == nil || c.processEvidence.NativeHost != a.Evidence.NativeHost || c.processEvidence.ChromeParent != a.Evidence.ChromeParent || g.broker.epoch != a.BrokerEpoch || c.epoch != a.ChannelEpoch || c.scopeHash != a.ScopeHash || !channelScopeQualified(c) || !c.executorQualified || !c.inventoryComplete || g.broker.closed || c.lifecycleInhibited || len(c.pending) != 0 || domUnknownBlockedLocked(c) || g.navigationRetired != nil || ctx.Err() != nil {
		return false
	}
	found := false
	for _, d := range c.documents {
		if d.ProfileChannel == a.Document.ProfileChannel && d.BrowserInstance == a.Document.BrowserInstance && d.TabID == a.Document.TabID && d.FrameID == 0 && d.DocumentID == a.Document.DocumentID && d.Origin == a.Document.Origin && d.Generation >= reply.Identity.Generation {
			found = true
		}
	}
	if !found {
		return false
	}
	for _, attempt := range c.attempts {
		if attempt.ControlLease != nil && *attempt.ControlLease == a.Lease {
			return false
		}
	}
	g.control = nil
	return true
}
