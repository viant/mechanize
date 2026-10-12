package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/viant/mechanize/auth"
)

// This sample describes Chrome extension window focus, not an OS foreground or
// omnibox proof, and never grants document or input authority.
type FocusedOriginMatch struct {
	Available             bool   `json:"available"`
	WindowFocused         bool   `json:"windowFocused"`
	MatchesExpectedOrigin bool   `json:"matchesExpectedOrigin"`
	Reason                string `json:"reason"`
	Evidence              string `json:"evidence,omitempty"`
	TabHandle             string `json:"tabHandle,omitempty"`
}
type focusedLocationRequest struct {
	Type           string `json:"type"`
	RequestID      string `json:"requestId"`
	BrokerEpoch    string `json:"brokerEpoch"`
	ChannelEpoch   string `json:"channelEpoch"`
	ScopeHash      string `json:"scopeHash"`
	DeadlineUnixMS int64  `json:"deadlineUnixMs"`
	ExpectedOrigin string `json:"expectedOrigin"`
}
type focusedLocationReply struct {
	Type                  string `json:"type"`
	RequestID             string `json:"requestId"`
	BrokerEpoch           string `json:"brokerEpoch"`
	ChannelEpoch          string `json:"channelEpoch"`
	ScopeHash             string `json:"scopeHash"`
	Available             bool   `json:"available"`
	WindowFocused         bool   `json:"windowFocused"`
	MatchesExpectedOrigin bool   `json:"matchesExpectedOrigin"`
	Reason                string `json:"reason"`
	TabID                 int64  `json:"tabId"`
}
type focusedLocationPending struct {
	request focusedLocationRequest
	conn    net.Conn
	done    chan focusedLocationReply
}

func locationUnavailable(reason string) FocusedOriginMatch { return FocusedOriginMatch{Reason: reason} }
func focusedReason(reason string) bool {
	switch reason {
	case "none", "noFocusedWindow", "ambiguousFocusedTab", "permissionUnavailable", "tabUnavailable", "pendingNavigation", "unsafeTab", "unsupportedLocation", "authorityChanged":
		return true
	}
	return false
}

// Recognized before private protocol dispatch: only this closed, correlated
// metadata response can bypass private output suppression. It changes no gates.
func (b *Broker) acceptFocusedLocationLocked(c *channel, conn net.Conn, data []byte) bool {
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &kind) != nil || kind.Type != "focusedLocationResult" {
		return false
	}
	p := c.focusedLocationPending
	if p == nil || p.conn != conn || c.conn != conn || len(data) > 2048 {
		return true
	}
	var response focusedLocationReply
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || decoder.Decode(new(any)) != io.EOF {
		return true
	}
	canonical, _ := json.Marshal(response)
	r := p.request
	if !bytes.Equal(canonical, data) || response.RequestID != r.RequestID || response.BrokerEpoch != r.BrokerEpoch || response.ChannelEpoch != r.ChannelEpoch || response.ScopeHash != r.ScopeHash || time.Now().UnixMilli() > r.DeadlineUnixMS || !focusedReason(response.Reason) || response.TabID < 0 || response.TabID > 9007199254740991 {
		return true
	}
	if !response.Available && response.WindowFocused {
		return true
	}
	if response.Available {
		if response.Reason != "none" || response.MatchesExpectedOrigin != (response.TabID > 0) {
			return true
		}
	} else if response.MatchesExpectedOrigin || response.TabID != 0 || response.Reason == "none" {
		return true
	}
	select {
	case p.done <- response:
	default:
	}
	return true
}
func (g *Gateway) MatchFocusedOrigin(ctx context.Context, p auth.Principal, origin string) (FocusedOriginMatch, error) {
	if authorize(ctx, p, false) != nil || !OrdinaryWebsiteOrigin(origin) {
		return FocusedOriginMatch{}, auth.ErrUnauthorized
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.ClientID != p.ClientID {
		return FocusedOriginMatch{}, auth.ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	b := g.broker
	b.mu.Lock()
	var selected []*channel
	unsupported := false
	for _, c := range b.channels {
		if c.grant.Principal.Namespace == p.Namespace && allowedOrigin(c.grant, origin) && c.conn != nil && !c.fixtureOnly && channelScopeQualified(c) {
			if c.focusedLocationVersion == 1 {
				selected = append(selected, c)
			} else {
				unsupported = true
			}
		}
	}
	b.mu.Unlock()
	if len(selected) == 0 {
		if unsupported {
			return locationUnavailable("unsupportedWorker"), nil
		}
		return locationUnavailable("noQualifiedChannel"), nil
	}
	if len(selected) > 16 {
		return locationUnavailable("ambiguousFocusedTab"), nil
	}
	type result struct{ value FocusedOriginMatch }
	done := make(chan result, len(selected))
	for _, c := range selected {
		go func(c *channel) { done <- result{g.matchFocusedChannel(ctx, c, origin)} }(c)
	}
	found := locationUnavailable("noFocusedWindow")
	count := 0
	for range selected {
		select {
		case item := <-done:
			if item.value.Available {
				count++
				found = item.value
			} else if found.Reason == "noFocusedWindow" && item.value.Reason != "noFocusedWindow" {
				found = item.value
			}
		case <-ctx.Done():
			return locationUnavailable("transportUnavailable"), nil
		}
	}
	if count > 1 {
		return locationUnavailable("ambiguousFocusedTab"), nil
	}
	return found, nil
}
func (g *Gateway) matchFocusedChannel(ctx context.Context, c *channel, origin string) FocusedOriginMatch {
	b := g.broker
	if b.checkChannelProcess(ctx, c, false) != nil {
		return locationUnavailable("authorityChanged")
	}
	deadline, _ := ctx.Deadline()
	b.mu.Lock()
	if b.closed || c.conn == nil || c.focusedLocationVersion != 1 || !channelScopeQualified(c) || c.focusedLocationPending != nil {
		b.mu.Unlock()
		return locationUnavailable("transportUnavailable")
	}
	pending := &focusedLocationPending{request: focusedLocationRequest{Type: "focusedLocation", RequestID: newID() + newID(), BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, DeadlineUnixMS: deadline.UnixMilli(), ExpectedOrigin: origin}, conn: c.conn, done: make(chan focusedLocationReply, 1)}
	c.focusedLocationPending = pending
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if c.focusedLocationPending == pending {
			c.focusedLocationPending = nil
		}
		b.mu.Unlock()
	}()
	written := make(chan error, 1)
	go func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		if ctx.Err() != nil {
			written <- ctx.Err()
			return
		}
		b.mu.Lock()
		same := c.conn == pending.conn && c.focusedLocationPending == pending && !b.closed
		b.mu.Unlock()
		if !same {
			written <- auth.ErrUnauthorized
			return
		}
		pending.conn.SetWriteDeadline(deadline)
		err := WriteFrame(pending.conn, pending.request)
		pending.conn.SetWriteDeadline(time.Time{})
		written <- err
	}()
	select {
	case err := <-written:
		if err != nil {
			return locationUnavailable("transportUnavailable")
		}
	case <-ctx.Done():
		return locationUnavailable("transportUnavailable")
	}
	var reply focusedLocationReply
	select {
	case reply = <-pending.done:
	case <-ctx.Done():
		return locationUnavailable("transportUnavailable")
	}
	if b.checkChannelProcess(ctx, c, false) != nil {
		return locationUnavailable("authorityChanged")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || c.conn != pending.conn || c.epoch != pending.request.ChannelEpoch || c.scopeHash != pending.request.ScopeHash || b.epoch != pending.request.BrokerEpoch || !channelScopeQualified(c) {
		return locationUnavailable("authorityChanged")
	}
	out := FocusedOriginMatch{Available: reply.Available, WindowFocused: reply.WindowFocused, MatchesExpectedOrigin: reply.MatchesExpectedOrigin, Reason: reply.Reason}
	if out.Available {
		out.Evidence = "extensionLastActiveTab"
		if out.WindowFocused {
			out.Evidence = "extensionFocusedTab"
		}
	}
	if out.MatchesExpectedOrigin {
		out.TabHandle = (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: int(reply.TabID)}}).QualifiedTabID()
	}
	return out
}
