package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// TabLocationMatch contains comparisons only, never the actual URL or title.
type TabLocationMatch struct {
	Available             bool   `json:"available"`
	MatchesExpectedOrigin bool   `json:"matchesExpectedOrigin"`
	PathChecked           bool   `json:"pathChecked"`
	MatchesExpectedPath   bool   `json:"matchesExpectedPath"`
	Reason                string `json:"reason"`
}

func ValidExpectedTabPath(origin, path string) bool {
	if !OrdinaryWebsiteOrigin(origin) || len(path) > 2048 {
		return false
	}
	if path == "" {
		return true
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\\\x00\r\n\t") {
		return false
	}
	u, e := url.Parse(origin + path)
	if e != nil || !utf8.ValidString(u.Path) {
		return false
	}
	for _, r := range u.Path {
		if unicode.IsControl(r) || r == '\\' {
			return false
		}
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return e == nil && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Scheme+"://"+u.Host == origin && u.EscapedPath() == path && !strings.Contains(path, "/../") && !strings.HasSuffix(path, "/..") && !strings.Contains(path, "/./") && !strings.HasSuffix(path, "/.")
}
func ownedTabParts(handle string) (string, string, int, bool) {
	if !model.OpaqueTabHandle(handle) {
		return "", "", 0, false
	}
	parts := strings.Split(handle, "/")
	id, e := strconv.Atoi(parts[2])
	return parts[0], parts[1], id, e == nil && id > 0 && id <= 2147483647 && strconv.Itoa(id) == parts[2]
}

type tabLocationRequest struct {
	Type           string `json:"type"`
	RequestID      string `json:"requestId"`
	TabID          int    `json:"tabId"`
	ExpectedOrigin string `json:"expectedOrigin"`
	ExpectedPath   string `json:"expectedPath"`
	BrokerEpoch    string `json:"brokerEpoch"`
	ChannelEpoch   string `json:"channelEpoch"`
	ScopeHash      string `json:"scopeHash"`
	DeadlineUnixMS int64  `json:"deadlineUnixMs"`
}
type tabLocationReply struct {
	Type         string `json:"type"`
	RequestID    string `json:"requestId"`
	BrokerEpoch  string `json:"brokerEpoch"`
	ChannelEpoch string `json:"channelEpoch"`
	ScopeHash    string `json:"scopeHash"`
	TabLocationMatch
}
type tabLocationPending struct {
	request tabLocationRequest
	conn    net.Conn
	done    chan TabLocationMatch
}

func tabLocationReason(s string) bool {
	switch s {
	case "none", "permissionUnavailable", "tabUnavailable", "pendingNavigation", "unsafeTab", "unsupportedLocation", "authorityChanged", "transportUnavailable", "noQualifiedChannel", "unsupportedWorker":
		return true
	}
	return false
}
func (b *Broker) acceptTabLocationLocked(c *channel, conn net.Conn, raw []byte) bool {
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil || kind.Type != "tabLocationResult" {
		return false
	}
	p := c.tabLocationPending
	if p == nil || p.conn != conn || c.conn != conn || len(raw) > 2048 {
		return true
	}
	var r tabLocationReply
	if closedPlaywright(raw, &r) != nil {
		return true
	}
	canonical, _ := json.Marshal(r)
	q := p.request
	if !bytes.Equal(raw, canonical) || r.RequestID != q.RequestID || r.BrokerEpoch != q.BrokerEpoch || r.ChannelEpoch != q.ChannelEpoch || r.ScopeHash != q.ScopeHash || !tabLocationReason(r.Reason) || time.Now().UnixMilli() > q.DeadlineUnixMS {
		return true
	}
	if r.Available {
		if r.Reason != "none" || r.PathChecked != (q.ExpectedPath != "") || r.MatchesExpectedPath && (!r.PathChecked || !r.MatchesExpectedOrigin) {
			return true
		}
	} else if r.Reason == "none" || r.MatchesExpectedOrigin || r.PathChecked || r.MatchesExpectedPath {
		return true
	}
	select {
	case p.done <- r.TabLocationMatch:
	default:
	}
	return true
}
func (g *Gateway) MatchTabLocation(ctx context.Context, p auth.Principal, handle, origin, path string) (TabLocationMatch, error) {
	denied := func(reason string) (TabLocationMatch, error) { return TabLocationMatch{Reason: reason}, nil }
	profile, browser, tabID, ok := ownedTabParts(handle)
	actual, e := auth.FromContext(ctx)
	if !ok || e != nil || actual.ClientID != p.ClientID || authorize(ctx, p, false) != nil || !ValidExpectedTabPath(origin, path) {
		return TabLocationMatch{}, auth.ErrUnauthorized
	}
	b := g.broker
	b.mu.Lock()
	c := b.channels[channelKey(profile, browser)]
	valid := c != nil && c.conn != nil && !c.fixtureOnly && channelScopeQualified(c) && c.grant.Principal.Namespace == p.Namespace && allowedOrigin(c.grant, origin)
	supported := valid && c.tabMetadataVersion == 1
	b.mu.Unlock()
	if !valid {
		return denied("noQualifiedChannel")
	}
	if !supported {
		return denied("unsupportedWorker")
	}
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	if b.checkChannelProcess(ctx, c, false) != nil {
		return denied("authorityChanged")
	}
	deadline, _ := ctx.Deadline()
	b.mu.Lock()
	if c.conn == nil || c.tabLocationPending != nil || b.closed {
		b.mu.Unlock()
		return denied("transportUnavailable")
	}
	pending := &tabLocationPending{request: tabLocationRequest{Type: "tabLocation", RequestID: newID() + newID(), TabID: tabID, ExpectedOrigin: origin, ExpectedPath: path, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, DeadlineUnixMS: deadline.UnixMilli()}, conn: c.conn, done: make(chan TabLocationMatch, 1)}
	c.tabLocationPending = pending
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if c.tabLocationPending == pending {
			c.tabLocationPending = nil
		}
		b.mu.Unlock()
	}()
	for !c.writeMu.TryLock() {
		select {
		case <-ctx.Done():
			return denied("transportUnavailable")
		case <-time.After(5 * time.Millisecond):
		}
	}
	b.mu.Lock()
	same := c.conn == pending.conn && c.tabLocationPending == pending && !b.closed
	b.mu.Unlock()
	if !same || ctx.Err() != nil {
		c.writeMu.Unlock()
		return denied("authorityChanged")
	}
	pending.conn.SetWriteDeadline(deadline)
	e = WriteFrame(pending.conn, pending.request)
	pending.conn.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()
	if e != nil {
		return denied("transportUnavailable")
	}
	var result TabLocationMatch
	select {
	case result = <-pending.done:
	case <-ctx.Done():
		return denied("transportUnavailable")
	}
	if b.checkChannelProcess(ctx, c, false) != nil {
		return denied("authorityChanged")
	}
	b.mu.Lock()
	same = c.conn == pending.conn && b.epoch == pending.request.BrokerEpoch && c.epoch == pending.request.ChannelEpoch && c.scopeHash == pending.request.ScopeHash && !b.closed
	b.mu.Unlock()
	if !same {
		return denied("authorityChanged")
	}
	return result, nil
}
