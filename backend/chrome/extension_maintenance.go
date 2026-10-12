package chrome

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
)

// ExtensionMaintenanceResult reports extension lifecycle observations only.
// A different boot/version never proves business completion or resolves input.
type ExtensionMaintenanceResult struct {
	AttemptID              string `json:"attemptId"`
	Outcome                string `json:"outcome"`
	Reason                 string `json:"reason"`
	DispatchState          string `json:"dispatchState"`
	Available              bool   `json:"available"`
	ObservedVersion        string `json:"observedVersion,omitempty"`
	BootChanged            bool   `json:"bootChanged"`
	MatchesExpectedVersion bool   `json:"matchesExpectedVersion"`
}
type extensionMaintenanceRequest struct {
	Type            string `json:"type"`
	RequestID       string `json:"requestId"`
	AttemptID       string `json:"attemptId"`
	ExpectedVersion string `json:"expectedVersion"`
	BrokerEpoch     string `json:"brokerEpoch"`
	ChannelEpoch    string `json:"channelEpoch"`
	ScopeHash       string `json:"scopeHash"`
	DeadlineUnixMS  int64  `json:"deadlineUnixMs"`
}
type extensionMaintenanceReply struct {
	Type                   string  `json:"type"`
	RequestID              string  `json:"requestId"`
	AttemptID              string  `json:"attemptId"`
	BrokerEpoch            string  `json:"brokerEpoch"`
	ChannelEpoch           string  `json:"channelEpoch"`
	ScopeHash              string  `json:"scopeHash"`
	Available              *bool   `json:"available,omitempty"`
	ObservedVersion        *string `json:"observedVersion,omitempty"`
	BootChanged            *bool   `json:"bootChanged,omitempty"`
	MatchesExpectedVersion *bool   `json:"matchesExpectedVersion,omitempty"`
	DispatchState          string  `json:"dispatchState"`
	Reason                 string  `json:"reason"`
}
type extensionMaintenancePending struct {
	request                     extensionMaintenanceRequest
	conn                        net.Conn
	evidence                    *nativepeer.ChromeProcessEvidence
	namespace, profile, browser string
	done                        chan extensionMaintenanceReply
}

func ValidExtensionVersion(v string) bool {
	if len(v) < 1 || len(v) > 23 {
		return false
	}
	parts := strings.Split(v, ".")
	if len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
		if _, e := strconv.ParseUint(part, 10, 16); e != nil {
			return false
		}
	}
	return true
}
func ExtensionMaintenanceAttemptID(p auth.Principal, session, request, profile, browser string) string {
	raw, _ := json.Marshal([]string{"mechanize.extension.maintenance.v1", p.Namespace, p.ClientID, session, request, profile, browser})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func extensionMaintenanceReason(reason string) bool {
	switch reason {
	case "none", "busy", "reloadRequested", "reloadUnconfirmed", "versionMismatch", "notFound", "authorityChanged", "receiptUnavailable", "receiptCapacity", "attemptConflict":
		return true
	}
	return false
}
func (b *Broker) maintenanceCurrentLocked(c *channel, p *extensionMaintenancePending) bool {
	return !b.closed && b.channels[channelKey(p.profile, p.browser)] == c && c.conn == p.conn && c.processEvidence == p.evidence && !c.fixtureOnly && channelScopeQualified(c) && c.grant.Principal.Namespace == p.namespace && b.epoch == p.request.BrokerEpoch && c.epoch == p.request.ChannelEpoch && c.scopeHash == p.request.ScopeHash && c.extensionMaintenancePending == p
}
func extensionMaintenanceIdle(c *channel) bool {
	// Dormant private protection and historical uncertainty remain untouched.
	// Only active exchanges or input/setup/lifecycle lanes block own reload.
	return c != nil && c.privateCredential == nil && c.privateAdvance == nil && c.privacyPending == nil && c.manualPending == nil && c.playwright == nil && c.openOriginPending == nil && len(c.pending) == 0 && c.reconnectBindings == nil && c.lifecycleGuard == nil
}
func (b *Broker) acceptExtensionMaintenanceLocked(c *channel, conn net.Conn, raw []byte) bool {
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil || kind.Type != "extension.reloadResult" && kind.Type != "extension.reloadStatusResult" {
		return false
	}
	p := c.extensionMaintenancePending
	if p == nil || p.conn != conn || !b.maintenanceCurrentLocked(c, p) || len(raw) > 2048 {
		return true
	}
	var r extensionMaintenanceReply
	if closedPlaywright(raw, &r) != nil {
		return true
	}
	canonical, _ := json.Marshal(r)
	q := p.request
	if !bytes.Equal(raw, canonical) || r.Type != q.Type+"Result" || r.RequestID != q.RequestID || r.AttemptID != q.AttemptID || r.BrokerEpoch != q.BrokerEpoch || r.ChannelEpoch != q.ChannelEpoch || r.ScopeHash != q.ScopeHash || time.Now().UnixMilli() >= q.DeadlineUnixMS || !extensionMaintenanceReason(r.Reason) || r.DispatchState != "unknown" && r.DispatchState != "notDispatched" {
		return true
	}
	status := q.Type == "extension.reloadStatus"
	if status {
		if r.Available == nil || r.ObservedVersion == nil || r.BootChanged == nil || r.MatchesExpectedVersion == nil {
			return true
		}
		if *r.Available {
			if !ValidExtensionVersion(*r.ObservedVersion) || r.DispatchState != "unknown" || *r.MatchesExpectedVersion != (*r.ObservedVersion == q.ExpectedVersion) || r.Reason == "none" && (!*r.BootChanged || !*r.MatchesExpectedVersion) {
				return true
			}
		} else if *r.ObservedVersion != "" || *r.BootChanged || *r.MatchesExpectedVersion || r.Reason == "none" {
			return true
		}
	} else if r.Available != nil || r.ObservedVersion != nil || r.BootChanged != nil || r.MatchesExpectedVersion != nil || r.Reason == "none" {
		return true
	}
	select {
	case p.done <- r:
	default:
	}
	return true
}
func (g *Gateway) maintenanceChannel(ctx context.Context, p auth.Principal, profile, browser string) (*channel, string, string, string) {
	if g == nil || g.broker == nil {
		return nil, "", "", "channelUnavailable"
	}
	actual, e := auth.FromContext(ctx)
	if e != nil || actual.ClientID == "" || actual.ClientID != p.ClientID || strings.HasPrefix(actual.ClientID, "controller:") || authorize(ctx, p, true) != nil {
		return nil, "", "", "nativeAuthorityRequired"
	}
	if (profile == "") != (browser == "") || profile != "" && (!receiptOpaqueID.MatchString(profile) || !receiptOpaqueID.MatchString(browser)) {
		return nil, "", "", "channelUnavailable"
	}
	b := g.broker
	b.mu.Lock()
	defer b.mu.Unlock()
	var selected *channel
	count := 0
	for _, c := range b.channels {
		if c.grant.Principal.Namespace == p.Namespace && (profile == "" || c.grant.ProfileChannel == profile && c.grant.BrowserInstance == browser) {
			selected = c
			count++
		}
	}
	if count != 1 || b.closed {
		return nil, "", "", "channelUnavailable"
	}
	return selected, selected.grant.ProfileChannel, selected.grant.BrowserInstance, ""
}
func (g *Gateway) extensionMaintenanceExchange(ctx context.Context, p auth.Principal, c *channel, attempt, expected string, status bool, admit func(context.Context) error) (ExtensionMaintenanceResult, error) {
	out := ExtensionMaintenanceResult{AttemptID: attempt, Outcome: "notDispatched", Reason: "channelUnavailable", DispatchState: "notDispatched"}
	if status {
		out.Outcome = "unknown"
		out.DispatchState = "unknown"
	}
	if !fingerprintV2Hash.MatchString(attempt) || !ValidExtensionVersion(expected) || g == nil || g.broker == nil || c == nil {
		return out, nil
	}
	b := g.broker
	if b.checkChannelProcess(ctx, c, false) != nil {
		out.Reason = "authorityChanged"
		return out, nil
	}
	if !status && (admit == nil || admit(ctx) != nil) {
		out.Reason = "nativeAuthorityRequired"
		return out, nil
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		out.Reason = "transportUnavailable"
		return out, nil
	}
	wireDeadline := time.Now().Add(3 * time.Second)
	if deadline.Before(wireDeadline) {
		wireDeadline = deadline
	}
	b.mu.Lock()
	if c.conn == nil || c.fixtureOnly || !channelScopeQualified(c) || b.closed || c.grant.Principal.Namespace != p.Namespace {
		b.mu.Unlock()
		return out, nil
	}
	if c.extensionMaintenanceVersion != 1 {
		b.mu.Unlock()
		out.Reason = "unsupportedWorker"
		return out, nil
	}
	if c.extensionMaintenancePending != nil || !status && !extensionMaintenanceIdle(c) {
		b.mu.Unlock()
		out.Reason = "busy"
		return out, nil
	}
	kind := "extension.reload"
	if status {
		kind = "extension.reloadStatus"
	}
	q := extensionMaintenanceRequest{Type: kind, RequestID: newID() + newID(), AttemptID: attempt, ExpectedVersion: expected, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, DeadlineUnixMS: wireDeadline.UnixMilli()}
	pending := &extensionMaintenancePending{request: q, conn: c.conn, evidence: c.processEvidence, namespace: p.Namespace, profile: c.grant.ProfileChannel, browser: c.grant.BrowserInstance, done: make(chan extensionMaintenanceReply, 1)}
	c.extensionMaintenancePending = pending
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if c.extensionMaintenancePending == pending {
			c.extensionMaintenancePending = nil
		}
		b.mu.Unlock()
	}()
	for !c.writeMu.TryLock() {
		select {
		case <-ctx.Done():
			out.Reason = "transportUnavailable"
			return out, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	if !status && admit(ctx) != nil {
		c.writeMu.Unlock()
		out.Reason = "nativeAuthorityRequired"
		return out, nil
	}
	b.mu.Lock()
	same := b.maintenanceCurrentLocked(c, pending) && (status || extensionMaintenanceIdle(c))
	if same && !status && ctx.Err() == nil {
		c.extensionMaintenanceBlocked = true
	}
	b.mu.Unlock()
	if !same || ctx.Err() != nil {
		b.mu.Lock()
		if !status && c.conn == pending.conn {
			c.extensionMaintenanceBlocked = false
		}
		b.mu.Unlock()
		c.writeMu.Unlock()
		out.Reason = "authorityChanged"
		return out, nil
	}
	// Once this write can reach the worker, uncertainty is retained. No retry of
	// extension.reload occurs here; later status is a separate read-only exchange.
	if !status {
		out.DispatchState = "unknown"
		out.Outcome = "unknown"
	}
	pending.conn.SetWriteDeadline(wireDeadline)
	e := WriteFrame(pending.conn, q)
	pending.conn.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()
	if e != nil {
		out.Reason = "transportUnavailable"
		return out, nil
	}
	timer := time.NewTimer(time.Until(wireDeadline))
	defer timer.Stop()
	var r extensionMaintenanceReply
	select {
	case r = <-pending.done:
	case <-ctx.Done():
		out.Reason = "transportUnavailable"
		return out, ctx.Err()
	case <-timer.C:
		out.Reason = "transportUnavailable"
		return out, nil
	}
	if b.checkChannelProcess(ctx, c, false) != nil {
		out.Reason = "authorityChanged"
		return out, nil
	}
	b.mu.Lock()
	same = b.maintenanceCurrentLocked(c, pending)
	b.mu.Unlock()
	if !same {
		out.Reason = "authorityChanged"
		return out, nil
	}
	out.Reason = r.Reason
	if !status {
		if r.DispatchState == "notDispatched" {
			b.mu.Lock()
			if c.conn == pending.conn {
				c.extensionMaintenanceBlocked = false
			}
			b.mu.Unlock()
		}
		out.DispatchState = r.DispatchState
		out.Outcome = r.DispatchState
		return out, nil
	}
	out.Available = *r.Available
	out.ObservedVersion = *r.ObservedVersion
	out.BootChanged = *r.BootChanged
	out.MatchesExpectedVersion = *r.MatchesExpectedVersion
	if out.Available && out.BootChanged && out.MatchesExpectedVersion && out.Reason == "none" {
		out.Outcome = "newBootObserved"
	}
	return out, nil
}
func (g *Gateway) ReloadExtension(ctx context.Context, p auth.Principal, session, request, profile, browser, expected string, admit func(context.Context) error) (ExtensionMaintenanceResult, error) {
	c, profile, browser, reason := g.maintenanceChannel(ctx, p, profile, browser)
	if reason != "" {
		return ExtensionMaintenanceResult{Outcome: "notDispatched", Reason: reason, DispatchState: "notDispatched"}, nil
	}
	attempt := ExtensionMaintenanceAttemptID(p, session, request, profile, browser)
	return g.extensionMaintenanceExchange(ctx, p, c, attempt, expected, false, admit)
}
func (g *Gateway) ExtensionReloadStatus(ctx context.Context, p auth.Principal, session, request, profile, browser, expected string) (ExtensionMaintenanceResult, error) {
	c, profile, browser, reason := g.maintenanceChannel(ctx, p, profile, browser)
	if reason != "" {
		return ExtensionMaintenanceResult{Outcome: "unknown", Reason: reason, DispatchState: "unknown"}, nil
	}
	attempt := ExtensionMaintenanceAttemptID(p, session, request, profile, browser)
	return g.extensionMaintenanceExchange(ctx, p, c, attempt, expected, true, nil)
}
