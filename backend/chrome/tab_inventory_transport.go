package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"sort"
	"time"

	"github.com/viant/mechanize/auth/nativepeer"
)

const maximumTabInventory = 200

type tabInventoryRequest struct {
	Type           string `json:"type"`
	RequestID      string `json:"requestId"`
	ExpectedOrigin string `json:"expectedOrigin"`
	BrokerEpoch    string `json:"brokerEpoch"`
	ChannelEpoch   string `json:"channelEpoch"`
	ScopeHash      string `json:"scopeHash"`
	DeadlineUnixMS int64  `json:"deadlineUnixMs"`
}
type tabInventoryReply struct {
	Type                            string `json:"type"`
	RequestID                       string `json:"requestId"`
	BrokerEpoch                     string `json:"brokerEpoch"`
	ChannelEpoch                    string `json:"channelEpoch"`
	ScopeHash                       string `json:"scopeHash"`
	TabIDs                          []int  `json:"tabIds"`
	Complete                        bool   `json:"complete"`
	Reason                          string `json:"reason"`
	profileChannel, browserInstance string
}
type tabInventoryPending struct {
	request                                    tabInventoryRequest
	namespace, profileChannel, browserInstance string
	conn                                       net.Conn
	evidence                                   *nativepeer.ChromeProcessEvidence
	done                                       chan tabInventoryReply
}

func (b *Broker) tabInventoryCurrentLocked(c *channel, p *tabInventoryPending) bool {
	return !b.closed && b.channels[channelKey(p.profileChannel, p.browserInstance)] == c && c.grant.Principal.Namespace == p.namespace && c.grant.ProfileChannel == p.profileChannel && c.grant.BrowserInstance == p.browserInstance && !c.fixtureOnly && c.conn == p.conn && c.processEvidence == p.evidence && b.epoch == p.request.BrokerEpoch && c.epoch == p.request.ChannelEpoch && c.scopeHash == p.request.ScopeHash && channelScopeQualified(c) && allowedOrigin(c.grant, p.request.ExpectedOrigin) && c.tabInventoryPending == p
}
func (b *Broker) acceptTabInventoryLocked(c *channel, conn net.Conn, raw []byte) bool {
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil || kind.Type != "tabInventoryResult" {
		return false
	}
	p := c.tabInventoryPending
	if p == nil || p.conn != conn || len(raw) > 4096 || !b.tabInventoryCurrentLocked(c, p) {
		return true
	}
	var r tabInventoryReply
	if closedPlaywright(raw, &r) != nil {
		return true
	}
	canonical, _ := json.Marshal(r)
	q := p.request
	if !bytes.Equal(raw, canonical) || r.RequestID != q.RequestID || r.BrokerEpoch != q.BrokerEpoch || r.ChannelEpoch != q.ChannelEpoch || r.ScopeHash != q.ScopeHash || time.Now().UnixMilli() >= q.DeadlineUnixMS || r.TabIDs == nil || len(r.TabIDs) > maximumTabInventory {
		return true
	}
	if r.Complete {
		if r.Reason != "none" {
			return true
		}
	} else {
		switch r.Reason {
		case "inventoryLimit":
		case "permissionUnavailable", "inventoryUnavailable", "authorityChanged":
			if len(r.TabIDs) != 0 {
				return true
			}
		default:
			return true
		}
	}
	seen := map[int]bool{}
	for _, id := range r.TabIDs {
		if id <= 0 || int64(id) > 2147483647 || seen[id] {
			return true
		}
		seen[id] = true
	}
	select {
	case p.done <- r:
	default:
	}
	return true
}

// Browser routing metadata needs no renderer lease or historical journal.
// It never clears an uncertain attempt or grants access to a protected document.
func (b *Broker) currentTabInventory(ctx context.Context, c *channel, namespace, origin string) (tabInventoryReply, string) {
	if ctx.Err() != nil {
		return tabInventoryReply{}, "transportUnavailable"
	}
	if b.checkChannelProcess(ctx, c, false) != nil {
		return tabInventoryReply{}, "authorityChanged"
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return tabInventoryReply{}, "transportUnavailable"
	}
	b.mu.Lock()
	if b.closed || c.grant.Principal.Namespace != namespace || c.conn == nil || c.fixtureOnly || !channelScopeQualified(c) || !allowedOrigin(c.grant, origin) {
		b.mu.Unlock()
		return tabInventoryReply{}, "noQualifiedChannel"
	}
	if c.tabInventoryVersion != 1 {
		b.mu.Unlock()
		return tabInventoryReply{}, "unsupportedWorker"
	}
	if c.tabInventoryPending != nil {
		b.mu.Unlock()
		return tabInventoryReply{}, "metadataBusy"
	}
	p := &tabInventoryPending{namespace: namespace, profileChannel: c.grant.ProfileChannel, browserInstance: c.grant.BrowserInstance, request: tabInventoryRequest{Type: "tabInventory", RequestID: newID() + newID(), ExpectedOrigin: origin, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, DeadlineUnixMS: deadline.UnixMilli()}, conn: c.conn, evidence: c.processEvidence, done: make(chan tabInventoryReply, 1)}
	c.tabInventoryPending = p
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if c.tabInventoryPending == p {
			c.tabInventoryPending = nil
		}
		b.mu.Unlock()
	}()
	for !c.writeMu.TryLock() {
		select {
		case <-ctx.Done():
			return tabInventoryReply{}, "transportUnavailable"
		case <-time.After(5 * time.Millisecond):
		}
	}
	b.mu.Lock()
	same := b.tabInventoryCurrentLocked(c, p)
	b.mu.Unlock()
	if !same || ctx.Err() != nil {
		c.writeMu.Unlock()
		return tabInventoryReply{}, "authorityChanged"
	}
	p.conn.SetWriteDeadline(deadline)
	e := WriteFrame(p.conn, p.request)
	p.conn.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()
	if e != nil {
		return tabInventoryReply{}, "transportUnavailable"
	}
	var reply tabInventoryReply
	select {
	case reply = <-p.done:
	case <-ctx.Done():
		return tabInventoryReply{}, "transportUnavailable"
	}
	if b.checkChannelProcess(ctx, c, false) != nil {
		return tabInventoryReply{}, "authorityChanged"
	}
	b.mu.Lock()
	same = b.tabInventoryCurrentLocked(c, p)
	b.mu.Unlock()
	if !same || ctx.Err() != nil {
		return tabInventoryReply{}, "authorityChanged"
	}
	sort.Ints(reply.TabIDs)
	reply.profileChannel, reply.browserInstance = p.profileChannel, p.browserInstance
	return reply, reply.Reason
}
