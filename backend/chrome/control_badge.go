package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/session"
)

// ControlBadgeWindow is browser-owned geometry only. Native presentation must
// independently match the exact signed process and a unique visible OS window.
// It is never a selector, input permit, or caller-supplied MCP parameter.
type ControlBadgeWindow struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type ControlBadgePresenter func(context.Context, auth.Principal, session.ProcessIdentity, ControlBadgeWindow) func()

func (w ControlBadgeWindow) valid() bool {
	for _, n := range []float64{w.X, w.Y, w.Width, w.Height} {
		if math.IsNaN(n) || math.IsInf(n, 0) || math.Abs(n) > 100000 {
			return false
		}
	}
	return w.Width >= 120 && w.Height >= 48
}

func playwrightOpened(raw json.RawMessage, requested bool) (*ControlBadgeWindow, bool) {
	var result struct {
		Opened bool                `json:"opened"`
		Window *ControlBadgeWindow `json:"controlBadgeWindow,omitempty"`
	}
	if closedPlaywright(raw, &result) != nil || !result.Opened || result.Window != nil && (!requested || !result.Window.valid()) {
		return nil, false
	}
	return result.Window, true
}

// This exchange is presentation-only and must be called after the enclosing
// operation's admission. The native presenter independently verifies PID/birth
// and unique OS geometry; no result here grants command or document authority.
type controlBadgeMetadataRequest struct {
	Type           string   `json:"type"`
	RequestID      string   `json:"requestId"`
	Identity       Identity `json:"identity"`
	BrokerEpoch    string   `json:"brokerEpoch"`
	ChannelEpoch   string   `json:"channelEpoch"`
	ScopeHash      string   `json:"scopeHash"`
	DeadlineUnixMS int64    `json:"deadlineUnixMs"`
}
type controlBadgeMetadataReply struct {
	Type         string              `json:"type"`
	RequestID    string              `json:"requestId"`
	BrokerEpoch  string              `json:"brokerEpoch"`
	ChannelEpoch string              `json:"channelEpoch"`
	ScopeHash    string              `json:"scopeHash"`
	Window       *ControlBadgeWindow `json:"window"`
}
type controlBadgePending struct {
	request controlBadgeMetadataRequest
	conn    net.Conn
	done    chan *ControlBadgeWindow
}
type controlBadgeContextKey struct{}
type controlBadgeHold struct {
	broker   *Broker
	channel  *channel
	identity Identity
	active   atomic.Bool
	live     atomic.Bool
}

func (b *Broker) acceptControlBadgeLocked(c *channel, conn net.Conn, raw []byte) bool {
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil || kind.Type != "controlBadgeMetadataResult" {
		return false
	}
	p := c.controlBadgePending
	if p == nil || p.conn != conn || c.conn != conn || len(raw) > 2048 {
		return true
	}
	var r controlBadgeMetadataReply
	if closedPlaywright(raw, &r) != nil {
		return true
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(raw, canonical) || r.RequestID != p.request.RequestID || r.BrokerEpoch != p.request.BrokerEpoch || r.ChannelEpoch != p.request.ChannelEpoch || r.ScopeHash != p.request.ScopeHash || time.Now().UnixMilli() > p.request.DeadlineUnixMS || r.Window != nil && !r.Window.valid() {
		return true
	}
	select {
	case p.done <- r.Window:
	default:
	}
	return true
}
func hasControlBadge(ctx context.Context, b *Broker, c *channel, i Identity) bool {
	held, ok := ctx.Value(controlBadgeContextKey{}).(*controlBadgeHold)
	return ok && held.broker == b && held.channel == c && held.active.Load() && sameReadDocument(Document{Identity: held.identity}, Document{Identity: i})
}
func (b *Broker) beginControlBadge(ctx context.Context, c *channel, i Identity) (context.Context, func()) {
	noop := func() {}
	if previous, ok := ctx.Value(controlBadgeContextKey{}).(*controlBadgeHold); ok && previous.broker == b && previous.channel == c && previous.live.Load() && sameReadDocument(Document{Identity: previous.identity}, Document{Identity: i}) {
		return ctx, noop
	}
	actor, err := auth.FromContext(ctx)
	if err != nil || actor.Validate() != nil || (!actor.HasScope("desktop:observe") && !actor.HasScope("desktop:control")) || i.TabID <= 0 || i.FrameID != 0 || i.DocumentID == "" || ctx.Err() != nil {
		return ctx, noop
	}
	b.mu.Lock()
	if b.controlBadge == nil || c == nil || c.controlBadgeVersion < 2 || c.controlBadgeVersion > 2 || c.conn == nil || b.closed || c.fixtureOnly || !channelScopeQualified(c) || c.processEvidence == nil || !c.processEvidence.KernelPeerQualified || c.grant.Principal.Namespace != actor.Namespace || i.ProfileChannel != c.grant.ProfileChannel || i.BrowserInstance != c.grant.BrowserInstance || c.controlBadgePending != nil {
		b.mu.Unlock()
		return ctx, noop
	}
	conn, evidence, presenter := c.conn, c.processEvidence, b.controlBadge
	bounded, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	deadline, _ := bounded.Deadline()
	pending := &controlBadgePending{request: controlBadgeMetadataRequest{Type: "controlBadgeMetadata", RequestID: newID() + newID(), Identity: i, BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, DeadlineUnixMS: deadline.UnixMilli()}, conn: conn, done: make(chan *ControlBadgeWindow, 1)}
	c.controlBadgePending = pending
	b.mu.Unlock()
	defer cancel()
	defer func() {
		b.mu.Lock()
		if c.controlBadgePending == pending {
			c.controlBadgePending = nil
		}
		b.mu.Unlock()
	}()
	hold := &controlBadgeHold{broker: b, channel: c, identity: i}
	hold.live.Store(true)
	next := context.WithValue(ctx, controlBadgeContextKey{}, hold)
	var end func()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			hold.active.Store(false)
			hold.live.Store(false)
			if end != nil {
				end()
			}
		})
	}
	// No write-lane wait can extend the caller or presentation deadline.
	for !c.writeMu.TryLock() {
		select {
		case <-bounded.Done():
			return next, stop
		case <-time.After(5 * time.Millisecond):
		}
	}
	b.mu.Lock()
	same := c.conn == conn && c.processEvidence == evidence && c.controlBadgePending == pending && b.epoch == pending.request.BrokerEpoch && c.epoch == pending.request.ChannelEpoch && c.scopeHash == pending.request.ScopeHash && !b.closed
	b.mu.Unlock()
	if !same || bounded.Err() != nil {
		c.writeMu.Unlock()
		return next, stop
	}
	conn.SetWriteDeadline(deadline)
	err = WriteFrame(conn, pending.request)
	conn.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()
	if err != nil {
		return next, stop
	}
	var window *ControlBadgeWindow
	select {
	case window = <-pending.done:
	case <-bounded.Done():
		return next, stop
	}
	b.mu.Lock()
	same = c.conn == conn && c.processEvidence == evidence && b.epoch == pending.request.BrokerEpoch && c.epoch == pending.request.ChannelEpoch && c.scopeHash == pending.request.ScopeHash && !b.closed
	b.mu.Unlock()
	if !same || window == nil || ctx.Err() != nil {
		return next, stop
	}
	end = presenter(ctx, actor, evidence.ChromeParent, *window)
	if end != nil {
		hold.active.Store(true)
	}
	after := context.AfterFunc(ctx, stop)
	return next, func() { after(); stop() }
}
