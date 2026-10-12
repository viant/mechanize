package chrome

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"time"

	"github.com/viant/mechanize/auth/nativepeer"
)

// Classification never changes the original receipt/outcome. Only the exact
// activation request sent by this broker can enter this map; no caller label or
// untyped UNKNOWN is treated as visibility-only.
type visibilityUnknown struct {
	request      openOriginRequest
	original     *nativepeer.ChromeProcessEvidence
	conn         net.Conn
	proven       *nativepeer.ChromeProcessEvidence
	quiescent    bool
	channelEpoch string
	scopeHash    string
}
type visibilityStatusRequest struct {
	Type                 string `json:"type"`
	RequestID            string `json:"requestId"`
	AttemptID            string `json:"attemptId"`
	BrokerEpoch          string `json:"brokerEpoch"`
	ChannelEpoch         string `json:"channelEpoch"`
	ScopeHash            string `json:"scopeHash"`
	DeadlineUnixMS       int64  `json:"deadlineUnixMs"`
	OriginalBrokerEpoch  string `json:"originalBrokerEpoch"`
	OriginalChannelEpoch string `json:"originalChannelEpoch"`
	OriginalScopeHash    string `json:"originalScopeHash"`
	Origin               string `json:"origin"`
	TabID                int    `json:"tabId"`
	FingerprintSHA256    string `json:"fingerprintSHA256"`
}
type visibilityStatusReply struct {
	Type         string `json:"type"`
	RequestID    string `json:"requestId"`
	AttemptID    string `json:"attemptId"`
	BrokerEpoch  string `json:"brokerEpoch"`
	ChannelEpoch string `json:"channelEpoch"`
	ScopeHash    string `json:"scopeHash"`
	Quiescent    bool   `json:"quiescent"`
}
type visibilityPending struct {
	request visibilityStatusRequest
	conn    net.Conn
	done    chan bool
}

func domUnknownBlockedLocked(c *channel) bool { return domUnknownOtherThanLocked(c, "") }
func domUnknownOtherThanLocked(c *channel, own string) bool {
	for id := range c.unknown {
		if id == own {
			continue
		}
		v := c.visibilityUnknown[id]
		if !visibilityUnknownQualifiedLocked(c, v) {
			return true
		}
	}
	return false
}
func visibilityUnknownQualifiedLocked(c *channel, v *visibilityUnknown) bool {
	if v != nil {
		if _, exists := c.attempts[v.request.AttemptID]; exists {
			return false
		}
	}
	return v != nil && v.request.Type == "browser.activateTab" && v.quiescent && c.conn != nil && v.conn == c.conn && v.proven != nil && v.proven == c.processEvidence && v.channelEpoch == c.epoch && v.scopeHash == c.scopeHash && c.openOriginPending == nil
}
func visibilityUnknownCountLocked(c *channel) int {
	n := 0
	for id := range c.unknown {
		if visibilityUnknownQualifiedLocked(c, c.visibilityUnknown[id]) {
			n++
		}
	}
	return n
}
func activationRequestFingerprint(profile, browser string, q openOriginRequest) string {
	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	encoder.SetEscapeHTML(false)
	if encoder.Encode([]any{"mechanize-browser-activate-tab-v1", profile, browser, q.AttemptID, q.Origin, q.TabID, q.BrokerEpoch, q.ChannelEpoch, q.ScopeHash}) != nil {
		return ""
	}
	raw := bytes.TrimSuffix(data.Bytes(), []byte("\n"))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func (b *Broker) acceptVisibilityStatusLocked(c *channel, conn net.Conn, raw []byte) bool {
	var kind struct{ Type string }
	if json.Unmarshal(raw, &kind) != nil || kind.Type != "browser.activationStatusResult" {
		return false
	}
	p := c.visibilityPending
	if p == nil || p.conn != conn || c.conn != conn || len(raw) > 2048 {
		return true
	}
	var r visibilityStatusReply
	if closedPlaywright(raw, &r) != nil {
		return true
	}
	canonical, _ := json.Marshal(r)
	q := p.request
	if !bytes.Equal(raw, canonical) || r.RequestID != q.RequestID || r.AttemptID != q.AttemptID || r.BrokerEpoch != q.BrokerEpoch || r.ChannelEpoch != q.ChannelEpoch || r.ScopeHash != q.ScopeHash || time.Now().UnixMilli() > q.DeadlineUnixMS {
		return true
	}
	select {
	case p.done <- r.Quiescent:
	default:
	}
	return true
}

// This read-only exchange proves terminal journal state and that the worker's
// serialized input lane has drained. An elapsed deadline alone is never proof.
func (b *Broker) qualifyVisibilityUnknown(ctx context.Context, c *channel) error {
	b.mu.Lock()
	var pendingIDs []string
	for id := range c.unknown {
		v := c.visibilityUnknown[id]
		if v == nil {
			b.mu.Unlock()
			return nil
		}
		if !visibilityUnknownQualifiedLocked(c, v) {
			pendingIDs = append(pendingIDs, id)
		}
	}
	b.mu.Unlock()
	for _, id := range pendingIDs {
		if err := b.checkChannelProcess(ctx, c, false); err != nil {
			return err
		}
		bounded, cancel := context.WithTimeout(ctx, time.Second)
		b.mu.Lock()
		v := c.visibilityUnknown[id]
		peer := c.processEvidence
		if v == nil || peer == nil || v.original == nil || peer.ChromeParent != v.original.ChromeParent || c.visibilityUnknownVersion != 1 || c.conn == nil || c.visibilityPending != nil || c.openOriginPending != nil || len(c.pending) != 0 || b.closed {
			b.mu.Unlock()
			cancel()
			return nil
		}
		deadline, _ := bounded.Deadline()
		q := visibilityStatusRequest{Type: "browser.activationStatus", RequestID: newID() + newID(), AttemptID: id, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, DeadlineUnixMS: deadline.UnixMilli(), OriginalBrokerEpoch: v.request.BrokerEpoch, OriginalChannelEpoch: v.request.ChannelEpoch, OriginalScopeHash: v.request.ScopeHash, Origin: v.request.Origin, TabID: v.request.TabID, FingerprintSHA256: activationRequestFingerprint(c.grant.ProfileChannel, c.grant.BrowserInstance, v.request)}
		p := &visibilityPending{request: q, conn: c.conn, done: make(chan bool, 1)}
		c.visibilityPending = p
		b.mu.Unlock()
		var err error
		for !c.writeMu.TryLock() {
			select {
			case <-bounded.Done():
				err = bounded.Err()
			case <-time.After(time.Millisecond):
			}
			if err != nil {
				break
			}
		}
		if err == nil {
			if bounded.Err() != nil {
				err = bounded.Err()
			} else {
				p.conn.SetWriteDeadline(deadline)
				err = WriteFrame(p.conn, q)
				p.conn.SetWriteDeadline(time.Time{})
			}
			c.writeMu.Unlock()
		}
		ready := false
		if err == nil {
			select {
			case ready = <-p.done:
			case <-bounded.Done():
				err = bounded.Err()
			}
		}
		if err == nil {
			err = b.checkChannelProcess(bounded, c, false)
		}
		b.mu.Lock()
		if c.visibilityPending == p {
			c.visibilityPending = nil
		}
		if err == nil && ready && c.conn == p.conn && c.processEvidence == peer && c.visibilityUnknown[id] == v && c.epoch == q.ChannelEpoch && b.epoch == q.BrokerEpoch && c.scopeHash == q.ScopeHash && !b.closed {
			v.quiescent = true
			v.conn = c.conn
			v.proven = peer
			v.channelEpoch = c.epoch
			v.scopeHash = c.scopeHash
		}
		b.mu.Unlock()
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}
