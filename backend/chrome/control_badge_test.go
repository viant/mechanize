package chrome

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/session"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPlaywrightBadgeOpenAcknowledgement(t *testing.T) {
	for _, tc := range []struct {
		raw                   string
		requested, ok, window bool
	}{
		{`{"opened":true}`, false, true, false},
		{`{"opened":true}`, true, true, false},
		{`{"opened":true,"controlBadgeWindow":{"x":10,"y":30,"width":1000,"height":700}}`, true, true, true},
		{`{"opened":true,"controlBadgeWindow":{"x":10,"y":30,"width":1000,"height":700}}`, false, false, false},
		{`{"opened":true,"controlBadgeWindow":{"x":10,"y":30,"width":1,"height":700}}`, true, false, false},
		{`{"opened":true,"controlBadgeWindow":{"x":10,"y":30,"width":1000,"height":700,"title":"private"}}`, true, false, false},
		{`{"opened":true,"url":"private"}`, true, false, false},
		{`{"opened":false}`, true, false, false},
	} {
		window, ok := playwrightOpened([]byte(tc.raw), tc.requested)
		if ok != tc.ok || (window != nil) != tc.window {
			t.Fatalf("requested=%v raw=%s got window=%v ok=%v", tc.requested, tc.raw, window, ok)
		}
	}
}

func TestControlBadgeMetadataPrivateLaneDeduplicatesAndCancels(t *testing.T) {
	g, p, base, c, conn := setupFixture(t)
	ctx, cancel := context.WithCancel(base)
	defer cancel()
	var starts, ends atomic.Int64
	g.broker.mu.Lock()
	c.controlBadgeVersion = 2
	c.privateFlow = &credentialFlow{}
	c.unknown["retained"] = true
	g.broker.controlBadge = func(_ context.Context, actor auth.Principal, _ session.ProcessIdentity, w ControlBadgeWindow) func() {
		if actor.ClientID != p.ClientID || !w.valid() {
			t.Error("bad presentation")
		}
		starts.Add(1)
		return func() { ends.Add(1) }
	}
	g.broker.mu.Unlock()
	identity := Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7, FrameID: 0, DocumentID: "doc", Generation: 1}
	go func() {
		raw, _ := ReadFrame(conn)
		var r controlBadgeMetadataRequest
		json.Unmarshal(raw, &r)
		WriteFrame(conn, controlBadgeMetadataReply{Type: "controlBadgeMetadataResult", RequestID: r.RequestID, BrokerEpoch: r.BrokerEpoch, ChannelEpoch: r.ChannelEpoch, ScopeHash: r.ScopeHash, Window: &ControlBadgeWindow{X: 10, Y: 20, Width: 1000, Height: 700}})
	}()
	held, end := g.broker.beginControlBadge(ctx, c, identity)
	if starts.Load() != 1 {
		t.Fatal("badge absent")
	}
	_, nestedEnd := g.broker.beginControlBadge(held, c, identity)
	nestedEnd()
	if ends.Load() != 0 {
		t.Fatal("nested lifetime ended outer")
	}
	cancel()
	waitControl(t, func() bool { return ends.Load() == 1 })
	end()
	if ends.Load() != 1 {
		t.Fatal("duplicate cleanup")
	}
	g.broker.mu.Lock()
	retained := c.privateFlow != nil && c.unknown["retained"] && len(c.pending) == 0
	g.broker.mu.Unlock()
	if !retained {
		t.Fatal("presentation altered private authority")
	}
}
func TestControlBadgeMetadataDeadlineAndMalformedReplyNeverAffectChannel(t *testing.T) {
	for _, mode := range []string{"deadline", "extra", "changed"} {
		t.Run(mode, func(t *testing.T) {
			g, _, base, c, conn := setupFixture(t)
			g.broker.mu.Lock()
			c.controlBadgeVersion = 2
			g.broker.controlBadge = func(context.Context, auth.Principal, session.ProcessIdentity, ControlBadgeWindow) func() {
				t.Error("unqualified badge shown")
				return func() {}
			}
			g.broker.mu.Unlock()
			identity := Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7, FrameID: 0, DocumentID: "doc", Generation: 1}
			go func() {
				raw, _ := ReadFrame(conn)
				var r controlBadgeMetadataRequest
				json.Unmarshal(raw, &r)
				if mode == "extra" {
					WriteFrame(conn, map[string]any{"type": "controlBadgeMetadataResult", "requestId": r.RequestID, "secret": "PRIVATE-CANARY"})
				}
				if mode == "changed" {
					g.broker.mu.Lock()
					c.epoch = "replacement"
					g.broker.mu.Unlock()
					WriteFrame(conn, controlBadgeMetadataReply{Type: "controlBadgeMetadataResult", RequestID: r.RequestID, BrokerEpoch: r.BrokerEpoch, ChannelEpoch: r.ChannelEpoch, ScopeHash: r.ScopeHash, Window: &ControlBadgeWindow{Width: 1000, Height: 700}})
				}
			}()
			ctx, cancel := context.WithTimeout(base, 35*time.Millisecond)
			defer cancel()
			start := time.Now()
			next, end := g.broker.beginControlBadge(ctx, c, identity)
			if hasControlBadge(next, g.broker, c, identity) {
				t.Fatal("failed metadata suppressed Playwright fallback")
			}
			end()
			if time.Since(start) > 200*time.Millisecond {
				t.Fatal("unbounded badge metadata")
			}
			g.broker.mu.Lock()
			okay := c.conn != nil && c.controlBadgePending == nil && len(c.unknown) == 0
			g.broker.mu.Unlock()
			if !okay {
				t.Fatal("badge failure altered execution state")
			}
		})
	}
}

func TestControlBadgeMetadataCanonicalReplyRejectsReorderedOrExtraFields(t *testing.T) {
	g, _, _, c, conn := setupFixture(t)
	q := controlBadgeMetadataRequest{RequestID: strings.Repeat("a", 64), BrokerEpoch: "b", ChannelEpoch: "c", ScopeHash: "s", DeadlineUnixMS: time.Now().Add(time.Second).UnixMilli()}
	valid := controlBadgeMetadataReply{Type: "controlBadgeMetadataResult", RequestID: q.RequestID, BrokerEpoch: q.BrokerEpoch, ChannelEpoch: q.ChannelEpoch, ScopeHash: q.ScopeHash, Window: &ControlBadgeWindow{X: 1, Y: 2, Width: 1000, Height: 700}}
	for _, mode := range []string{"canonical", "reordered", "extra"} {
		g.broker.mu.Lock()
		pending := &controlBadgePending{request: q, conn: c.conn, done: make(chan *ControlBadgeWindow, 1)}
		c.controlBadgePending = pending
		raw, _ := json.Marshal(valid)
		if mode != "canonical" {
			var m map[string]any
			json.Unmarshal(raw, &m)
			if mode == "extra" {
				m["title"] = "PRIVATE-CANARY"
			}
			raw, _ = json.Marshal(m)
		}
		handled := g.broker.acceptControlBadgeLocked(c, c.conn, raw)
		g.broker.mu.Unlock()
		if !handled {
			t.Fatal("metadata escaped")
		}
		select {
		case <-pending.done:
			if mode != "canonical" {
				t.Fatal("noncanonical metadata admitted")
			}
		default:
			if mode == "canonical" {
				t.Fatal("canonical metadata rejected")
			}
		}
	}
	_ = conn
}
