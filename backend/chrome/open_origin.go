package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

// OpenOrigin is a channel operation, not a renderer lease or page readiness proof.
type openOriginRequest struct {
	Type           string `json:"type"`
	RequestID      string `json:"requestId"`
	AttemptID      string `json:"attemptId"`
	Origin         string `json:"origin"`
	BrokerEpoch    string `json:"brokerEpoch"`
	ChannelEpoch   string `json:"channelEpoch"`
	ScopeHash      string `json:"scopeHash"`
	DeadlineUnixMS int64  `json:"deadlineUnixMs"`
	ControlBadge   bool   `json:"controlBadge,omitempty"`
	TabID          int    `json:"tabId,omitempty"`
}
type openOriginReply struct {
	Type               string              `json:"type"`
	RequestID          string              `json:"requestId"`
	AttemptID          string              `json:"attemptId"`
	BrokerEpoch        string              `json:"brokerEpoch"`
	ChannelEpoch       string              `json:"channelEpoch"`
	ScopeHash          string              `json:"scopeHash"`
	DispatchState      string              `json:"dispatchState"`
	TabID              int                 `json:"tabId"`
	ErrorCode          string              `json:"errorCode"`
	ControlBadgeWindow *ControlBadgeWindow `json:"controlBadgeWindow,omitempty"`
}
type openOriginPending struct {
	request openOriginRequest
	conn    net.Conn
	done    chan openOriginReply
}
type openOriginContextKey struct{}
type openOriginAdmission struct {
	action                                       string
	tabID                                        int
	gateway                                      *Gateway
	channel                                      *channel
	conn                                         net.Conn
	principal                                    auth.Principal
	origin, brokerEpoch, channelEpoch, scopeHash string
	evidence                                     *nativepeer.ChromeProcessEvidence
	used                                         atomic.Bool
}

func openOriginError(code, state string) error {
	return browserError(code, "Background tab creation unavailable", state)
}

// Tab visibility uses the authenticated browser channel, not a renderer lease.
// Its input lane and retained UNKNOWN/private/lifecycle barriers still apply.
func tabActivationIdle(c *channel) bool {
	return c != nil && c.grant.Principal.HasScope("desktop:control") && c.conn != nil && channelScopeQualified(c) && !c.fixtureOnly && !c.lifecycleInhibited && c.lifecycleGuard == nil && len(c.unknown) == 0 && len(c.pending) == 0 && c.playwright == nil && c.privateInspection == nil && c.privateCredential == nil && c.privateAdvance == nil && c.privacyPending == nil && c.manualPending == nil && c.openOriginPending == nil
}
func openOriginIdle(c *channel) bool {
	return c != nil && c.executorQualified && tabActivationIdle(c)
}
func browserOperationIdle(c *channel, action string) bool {
	if action == "browser.activateTab" {
		return tabActivationIdle(c)
	}
	return action == "browser.openOrigin" && openOriginIdle(c)
}
func (g *Gateway) PrepareOpenOrigin(ctx context.Context, p auth.Principal, origin string) (context.Context, int, error) {
	return g.prepareBrowserOperation(ctx, p, origin, "", "browser.openOrigin")
}
func (g *Gateway) PrepareActivateTab(ctx context.Context, p auth.Principal, origin, handle string) (context.Context, int, error) {
	return g.prepareBrowserOperation(ctx, p, origin, handle, "browser.activateTab")
}
func operationError(action, code, state string) error {
	if action == "browser.activateTab" {
		code = strings.Replace(code, "openOrigin", "tabActivation", 1)
	}
	return browserError(code, "Browser operation unavailable", state)
}
func (g *Gateway) prepareBrowserOperation(ctx context.Context, p auth.Principal, origin, handle, action string) (context.Context, int, error) {
	profile, browser, tabID, valid := ownedTabParts(handle)
	if action == "browser.activateTab" && !valid {
		return ctx, 0, auth.ErrUnauthorized
	}

	if authorize(ctx, p, true) != nil || !OrdinaryWebsiteOrigin(origin) || ctx.Err() != nil {
		return ctx, 0, auth.ErrUnauthorized
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.ClientID != p.ClientID {
		return ctx, 0, auth.ErrUnauthorized
	}
	b := g.broker
	b.mu.Lock()
	var selected *channel
	count := 0
	for _, c := range b.channels {
		if (handle == "" || c.grant.ProfileChannel == profile && c.grant.BrowserInstance == browser) && c.grant.Principal.Namespace == p.Namespace && allowedOrigin(c.grant, origin) && c.conn != nil && channelScopeQualified(c) && !c.fixtureOnly {
			selected = c
			count++
		}
	}
	if count != 1 {
		b.mu.Unlock()
		return ctx, 0, operationError(action, "openOriginChannelUnavailable", "notDispatched")
	}
	if action == "browser.openOrigin" && selected.openOriginVersion != 1 || action == "browser.activateTab" && selected.tabMetadataVersion != 1 {
		b.mu.Unlock()
		return ctx, 0, openOriginError("unsupportedWorker", "notDispatched")
	}
	if !browserOperationIdle(selected, action) {
		b.mu.Unlock()
		return ctx, 0, operationError(action, "openOriginBusy", "notDispatched")
	}
	a := &openOriginAdmission{action: action, tabID: tabID, gateway: g, channel: selected, conn: selected.conn, principal: p, origin: origin, brokerEpoch: b.epoch, channelEpoch: selected.epoch, scopeHash: selected.scopeHash, evidence: selected.processEvidence}
	b.openOriginGeneration++
	epoch := b.openOriginGeneration
	b.mu.Unlock()
	if err = b.checkChannelProcess(ctx, selected, false); err != nil {
		return ctx, 0, err
	}
	return context.WithValue(ctx, openOriginContextKey{}, a), int(epoch), nil
}
func (g *Gateway) ExecuteOpenOrigin(ctx context.Context, p auth.Principal, origin, attemptID string, admit func(context.Context) error) (integration.StepResult, error) {
	return g.executeBrowserOperation(ctx, p, origin, "", attemptID, "browser.openOrigin", admit, nil)
}
func (g *Gateway) ExecuteActivateTab(ctx context.Context, p auth.Principal, origin, handle, attemptID string, admit func(context.Context) error) (integration.StepResult, error) {
	return g.executeBrowserOperation(ctx, p, origin, handle, attemptID, "browser.activateTab", admit, nil)
}

func (g *Gateway) ExecuteActivateTabBound(ctx context.Context, p auth.Principal, origin, handle, attemptID string, admit func(context.Context) error, commit func(context.Context, ActivationBinding) error) (integration.StepResult, error) {
	if commit == nil {
		return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, auth.ErrUnauthorized
	}
	return g.executeBrowserOperation(ctx, p, origin, handle, attemptID, "browser.activateTab", admit, commit)
}
func (g *Gateway) executeBrowserOperation(ctx context.Context, p auth.Principal, origin, handle, attemptID, action string, admit func(context.Context) error, commit func(context.Context, ActivationBinding) error) (integration.StepResult, error) {

	result := integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	a, ok := ctx.Value(openOriginContextKey{}).(*openOriginAdmission)
	actual, actualErr := auth.FromContext(ctx)
	if actualErr != nil || actual.ClientID != p.ClientID {
		return result, auth.ErrUnauthorized
	}
	if !ok || a.action != action || a.gateway != g || a.origin != origin || a.principal.Namespace != p.Namespace || a.principal.ClientID != p.ClientID || authorize(ctx, p, true) != nil || !fingerprintV2Hash.MatchString(attemptID) || admit == nil || !a.used.CompareAndSwap(false, true) {
		return result, auth.ErrUnauthorized
	}
	if action == "browser.activateTab" {
		profile, browser, tabID, valid := ownedTabParts(handle)
		if !valid || tabID != a.tabID || profile != a.channel.grant.ProfileChannel || browser != a.channel.grant.BrowserInstance {
			return result, auth.ErrUnauthorized
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := admit(ctx); err != nil {
		return result, err
	}
	b, c := g.broker, a.channel
	if err := b.checkChannelProcess(ctx, c, false); err != nil {
		return result, err
	}
	deadline, _ := ctx.Deadline()
	pending := &openOriginPending{request: openOriginRequest{Type: action, TabID: a.tabID, RequestID: newID() + newID(), AttemptID: attemptID, Origin: origin, BrokerEpoch: a.brokerEpoch, ChannelEpoch: a.channelEpoch, ScopeHash: a.scopeHash, DeadlineUnixMS: deadline.UnixMilli()}, conn: a.conn, done: make(chan openOriginReply, 1)}
	b.mu.Lock()
	if b.closed || c.conn != a.conn || b.epoch != a.brokerEpoch || c.epoch != a.channelEpoch || c.scopeHash != a.scopeHash || !browserOperationIdle(c, action) {
		b.mu.Unlock()
		return result, operationError(action, "openOriginAuthorityChanged", "notDispatched")
	}
	pending.request.ControlBadge = b.controlBadge != nil && c.controlBadgeVersion == 2
	c.invalidateConsentReconnect()
	c.openOriginPending = pending
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if c.openOriginPending == pending {
			c.openOriginPending = nil
		}
		b.mu.Unlock()
	}()
	if action == "browser.activateTab" && commit != nil {
		binding, e := a.activationBinding(ctx, p, attemptID)
		if e != nil {
			return result, operationError(action, "openOriginAuthorityChanged", "notDispatched")
		}
		// No native command has been written. Failure or missing exact durable
		// readback is a pre-input refusal, never a recoverable phantom intent.
		if e = commit(ctx, binding); e != nil {
			return result, operationError(action, "tabActivationUnavailable", "notDispatched")
		}
		if e = b.checkChannelProcess(ctx, c, false); e != nil {
			return result, e
		}
		if _, e = a.activationBinding(ctx, p, attemptID); e != nil {
			return result, operationError(action, "openOriginAuthorityChanged", "notDispatched")
		}
	}
	for !c.writeMu.TryLock() {
		select {
		case <-ctx.Done():
			return result, operationError(action, "openOriginDeadline", "notDispatched")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if err := admit(ctx); err != nil {
		c.writeMu.Unlock()
		return result, err
	}
	b.mu.Lock()
	same := c.conn == a.conn && c.openOriginPending == pending && b.epoch == a.brokerEpoch && c.epoch == a.channelEpoch && c.scopeHash == a.scopeHash && !b.closed && (action != "browser.activateTab" || c.processEvidence == a.evidence)
	b.mu.Unlock()
	if !same || ctx.Err() != nil {
		c.writeMu.Unlock()
		return result, operationError(action, "openOriginAuthorityChanged", "notDispatched")
	}
	// Once a write can reach Chrome, a missing reply is unknown; the durable Host
	// attempt and shared extension intent prevent automatic replay.
	result.DispatchState = "unknown"
	a.conn.SetWriteDeadline(deadline)
	err := WriteFrame(a.conn, pending.request)
	a.conn.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()
	unknown := func(code string) (integration.StepResult, error) {
		b.mu.Lock()
		if c.unknown == nil {
			c.unknown = map[string]bool{}
		}
		c.unknown[attemptID] = true
		if action == "browser.activateTab" {
			if c.visibilityUnknown == nil {
				c.visibilityUnknown = map[string]*visibilityUnknown{}
			}
			if c.visibilityUnknown[attemptID] == nil {
				c.visibilityUnknown[attemptID] = &visibilityUnknown{request: pending.request, original: a.evidence}
			}
		}
		b.mu.Unlock()
		return result, operationError(action, code, "unknown")
	}
	if err != nil {
		return unknown("openOriginUnknown")
	}
	var reply openOriginReply
	select {
	case reply = <-pending.done:
	case <-ctx.Done():
		return unknown("openOriginUnknown")
	}
	if reply.DispatchState == "notDispatched" {
		result.DispatchState = "notDispatched"
		return result, operationError(action, reply.ErrorCode, "notDispatched")
	}
	if err = b.checkChannelProcess(ctx, c, false); err != nil {
		return unknown("openOriginUnknown")
	}
	b.mu.Lock()
	same = c.conn == a.conn && c.epoch == a.channelEpoch && c.scopeHash == a.scopeHash && b.epoch == a.brokerEpoch
	b.mu.Unlock()
	if !same {
		return unknown("openOriginUnknown")
	}
	result.DispatchState = reply.DispatchState
	if reply.DispatchState == "dispatched" {
		result.VerificationState = "verified" // Chrome confirmed tab creation only; no page readiness claim.
		if reply.ControlBadgeWindow != nil {
			b.mu.Lock()
			presenter, evidence := b.controlBadge, c.processEvidence
			b.mu.Unlock()
			if presenter != nil && evidence != nil {
				if end := presenter(ctx, p, evidence.ChromeParent, *reply.ControlBadgeWindow); end != nil {
					defer end()
				}
			}
		}
		if action == "browser.openOrigin" {
			result.Value = &model.Value{Kind: model.StringValue, String: (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: reply.TabID}}).QualifiedTabID()}
		}
		return result, nil
	}
	if reply.DispatchState == "unknown" {
		// Only the authenticated, closed reply decoder can supply this reason.
		return unknown(reply.ErrorCode)
	}
	return result, operationError(action, reply.ErrorCode, "notDispatched")
}
func (b *Broker) acceptOpenOriginLocked(c *channel, conn net.Conn, data []byte) bool {
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &kind) != nil || kind.Type != "browser.openOriginResult" && kind.Type != "browser.activateTabResult" {
		return false
	}
	p := c.openOriginPending
	if p == nil || p.conn != conn || c.conn != conn || len(data) > 2048 {
		return true
	}
	var r openOriginReply
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
		return true
	}
	canonical, _ := json.Marshal(r)
	q := p.request
	if r.Type != q.Type+"Result" || !bytes.Equal(canonical, data) || r.RequestID != q.RequestID || r.AttemptID != q.AttemptID || r.BrokerEpoch != q.BrokerEpoch || r.ChannelEpoch != q.ChannelEpoch || r.ScopeHash != q.ScopeHash || time.Now().UnixMilli() > q.DeadlineUnixMS {
		return true
	}
	switch r.ErrorCode {
	case "none", "authorityChanged", "permissionUnavailable", "windowUnavailable", "receiptCapacity", "unknownEffect", "lifecycleInhibited", "creationUnavailable", "receiptUnavailable", "attemptConflict", "originDenied", "tabUnavailable", "activationUnavailable":
	default:
		return true
	}
	if r.ControlBadgeWindow != nil && (!p.request.ControlBadge || !r.ControlBadgeWindow.valid() || r.DispatchState != "dispatched") {
		return true
	}
	if r.DispatchState == "dispatched" {
		if r.TabID <= 0 || r.ErrorCode != "none" || q.Type == "browser.activateTab" && r.TabID != q.TabID {
			return true
		}
	} else if (r.DispatchState != "unknown" && r.DispatchState != "notDispatched") || r.TabID != 0 || r.ErrorCode == "none" {
		return true
	}
	select {
	case p.done <- r:
	default:
	}
	return true
}
