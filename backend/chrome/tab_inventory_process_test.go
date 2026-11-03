package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth/nativepeer"
)

func TestOperationalInventoryRetiresOnlyConfirmedChangedPeer(t *testing.T) {
	for _, mode := range []string{"chrome", "host", "unavailable", "cancelled", "timeout", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			g, p, base, c, conn := liveTabInventoryFixture(t, 1)
			b := g.broker
			b.mu.Lock()
			expected := *c.processEvidence
			c.unknown["retained-original"] = true
			original := c.conn
			b.mu.Unlock()
			ctx, cancel := context.WithTimeout(base, time.Second)
			defer cancel()
			var replacement net.Conn
			b.verifyPeer = func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
				current := expected
				switch mode {
				case "chrome":
					current.ChromeParent.StartToken = "changed"
				case "host":
					current.NativeHost.StartToken = "changed"
				case "unavailable":
					return current, errors.New("unavailable observation")
				case "timeout":
					return current, context.DeadlineExceeded
				case "cancelled":
					cancel()
					return current, context.Canceled
				case "replacement":
					current.ChromeParent.StartToken = "changed"
					var peer net.Conn
					replacement, peer = net.Pipe()
					t.Cleanup(func() { replacement.Close(); peer.Close() })
					b.mu.Lock()
					c.conn = replacement
					b.mu.Unlock()
				}
				return current, nil
			}
			result, err := g.ListTabHandles(ctx, p, c.grant.Origins[0])
			if result.Complete || len(result.Tabs) != 0 || result.Reason != "authorityChanged" {
				t.Fatal("invalid peer returned inventory", result, err)
			}
			if mode == "chrome" || mode == "host" {
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				data := make([]byte, 1)
				n, e := conn.Read(data)
				if n != 0 || e == nil {
					t.Fatal("input was sent or stale connection retained")
				}
				var timeout net.Error
				if errors.As(e, &timeout) && timeout.Timeout() {
					t.Fatal("changed peer was not closed")
				}
			} else {
				b.mu.Lock()
				live := c.conn
				retained := c.unknown["retained-original"]
				b.mu.Unlock()
				want := original
				if replacement != nil {
					want = replacement
				}
				if live != want || !retained {
					t.Fatal("uncertain/replaced peer or ledger changed")
				}
				if replacement != nil {
					_ = replacement.SetDeadline(time.Now().Add(time.Second))
				} else if e := original.SetDeadline(time.Now().Add(time.Second)); e != nil {
					t.Fatal("uncertain peer was closed", e)
				}
			}
			b.mu.Lock()
			retained := c.unknown["retained-original"]
			b.mu.Unlock()
			if !retained {
				t.Fatal("unresolved effect discarded")
			}
		})
	}
}

func TestFreshHandshakeAfterInventoryRetirementRetainsUnknownHistory(t *testing.T) {
	g, p, ctx, c, old := liveTabInventoryFixture(t, 1)
	b := g.broker
	b.mu.Lock()
	current := *c.processEvidence
	c.unknown["retained-original"] = true
	grant := c.grant
	b.mu.Unlock()
	current.ChromeParent.StartToken = "new-verified-birth"
	current.Ancestors = append(current.Ancestors[:0:0], current.ChromeParent)
	b.verifyPeer = func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) { return current, nil }
	out, e := g.ListTabHandles(ctx, p, grant.Origins[0])
	if e != nil || out.Complete || out.Reason != "authorityChanged" {
		t.Fatal("changed peer accepted", out, e)
	}
	old.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = ReadFrame(old); e == nil {
		t.Fatal("old peer was not retired")
	}
	waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.conn == nil })
	conn, e := net.Dial("unix", b.listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if e = WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "setupMetadataVersion": 1, "tabInventoryVersion": 1, "profileChannel": grant.ProfileChannel, "browserInstance": grant.BrowserInstance, "extensionOrigin": grant.ExtensionOrigin, "credential": strings.Repeat("synthetic", 8), "trustScope": TrustScopeDesktop}); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadFrame(conn); e != nil {
		t.Fatal(e)
	}
	waitControl(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return c.conn != nil && c.processEvidence != nil && c.processEvidence.ChromeParent == current.ChromeParent
	})
	done := make(chan error, 1)
	go func() {
		raw, e := ReadFrame(conn)
		if e != nil {
			done <- e
			return
		}
		var q tabInventoryRequest
		if e = json.Unmarshal(raw, &q); e != nil {
			done <- e
			return
		}
		if q.Type != "tabInventory" {
			done <- errors.New("unexpected browser command")
			return
		}
		done <- WriteFrame(conn, tabInventoryTestReply(q))
	}()
	out, e = g.ListTabHandles(ctx, p, grant.Origins[0])
	if e != nil || !out.Complete || len(out.Tabs) != 1 {
		t.Fatal("fresh authenticated inventory unavailable", out, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	b.mu.Lock()
	retained := c.unknown["retained-original"]
	sameOwner := c.grant.Principal.Namespace == grant.Principal.Namespace
	b.mu.Unlock()
	if !retained || !sameOwner {
		t.Fatal("reconnect discarded history or changed owner")
	}
}
