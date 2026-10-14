package chrome

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth/nativepeer"
)

func TestStatusRefreshDoesNotQueryAnOriginalInputStillOwnedByItsPendingFlight(t *testing.T) {
	var queries atomic.Int32
	g, p, ctx, inputs := controlFixtureVersion(t, 2, func() string { queries.Add(1); return "matching" })
	b := g.broker
	b.mu.Lock()
	c := b.channels[channelKey("p1", "b1")]
	id := strings.Repeat("a", 64)
	command := Command{RequestID: "original-input", Action: "element.press", Identity: c.documents[0].Identity, AttemptID: id, FingerprintVersion: 2, FingerprintSHA256: strings.Repeat("b", 64), BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, ControlLease: &Lease{ID: "original-lease", Generation: 1}}
	c.attempts[id] = command
	c.unknown[id] = true
	c.pending[command.RequestID] = &pending{command: command, mutation: true}
	b.mu.Unlock()

	status, err := g.BrowserStatus(ctx, p)
	if err != nil || len(status.Channels) != 1 {
		t.Fatal("status failed", err)
	}
	if queries.Load() != 0 || status.Channels[0].PendingCount != 1 || status.Channels[0].UnknownCount != 1 {
		t.Fatalf("status queried/rewrote the owned input: queries=%d pending=%d unknown=%d", queries.Load(), status.Channels[0].PendingCount, status.Channels[0].UnknownCount)
	}
	if inputs.Load() != 0 {
		t.Fatal("metadata dispatched input")
	}
	b.mu.Lock()
	delete(c.pending, command.RequestID)
	b.mu.Unlock()
	status, err = g.BrowserStatus(ctx, p)
	if err != nil || queries.Load() != 1 || status.Channels[0].UnknownCount != 0 || inputs.Load() != 0 {
		t.Fatal("settled original receipt was not reconciled observationally", err)
	}
}

func TestReceiptQueryAdmissionRejectsOwnerStartedAfterStatusSelection(t *testing.T) {
	for _, route := range []string{"status", "direct"} {
		for _, owner := range []string{"input", "playwright"} {
			t.Run(route+"/"+owner, func(t *testing.T) {
				var queries atomic.Int32
				g, p, ctx, inputs := controlFixtureVersion(t, 2, func() string { queries.Add(1); return "matching" })
				b := g.broker
				b.mu.Lock()
				c := b.channels[channelKey("p1", "b1")]
				id := strings.Repeat("a", 64)
				original := Command{Action: "element.press", Identity: c.documents[0].Identity, AttemptID: id, FingerprintVersion: 2, FingerprintSHA256: strings.Repeat("b", 64), BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash}
				c.attempts[id], c.unknown[id] = original, true
				b.mu.Unlock()
				var started atomic.Bool
				verify := b.verifyPeer
				// The first process check is reached after status selected its ID
				// (or direct QueryReceipt selected its original), before admission.
				b.verifyPeer = func(current context.Context, conn *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
					if started.CompareAndSwap(false, true) {
						b.mu.Lock()
						command := original
						command.RequestID = "new-owner"
						if owner == "playwright" {
							command.Identity.TabID++ // even an independent CDP owner needs exclusivity
							c.playwright = &playwrightExecution{command: command}
						}
						c.pending[command.RequestID] = &pending{command: command, mutation: true, playwright: owner == "playwright"}
						b.mu.Unlock()
					}
					return verify(current, conn)
				}
				if route == "status" {
					if _, err := g.BrowserStatus(ctx, p); err != nil {
						t.Fatal("metadata status failed", err)
					}
				} else if _, err := b.QueryReceipt(ctx, p, id); err == nil {
					t.Error("direct query crossed the active owner")
				}
				b.mu.Lock()
				pendingCount, unknown := len(c.pending), c.unknown[id]
				_, received := c.receipts[id]
				c.playwright = nil
				delete(c.pending, "new-owner")
				b.mu.Unlock()
				if !started.Load() || queries.Load() != 0 || pendingCount != 1 || !unknown || received || inputs.Load() != 0 {
					t.Fatalf("query admitted after owner started: started=%t queries=%d pending=%d unknown=%t received=%t inputs=%d", started.Load(), queries.Load(), pendingCount, unknown, received, inputs.Load())
				}
				if _, err := b.QueryReceipt(ctx, p, id); err != nil || queries.Load() != 1 || inputs.Load() != 0 {
					t.Fatal("original query did not resume observationally after owner drained", err)
				}
			})
		}
	}
}

func TestStatusRefreshLeavesPlaywrightOwnerExclusiveButAllowsOrdinaryMetadataPending(t *testing.T) {
	for _, mode := range []string{"playwright", "metadata", "independentInput"} {
		t.Run(mode, func(t *testing.T) {
			var queries atomic.Int32
			g, p, ctx, inputs := controlFixtureVersion(t, 2, func() string { queries.Add(1); return "matching" })
			b := g.broker
			b.mu.Lock()
			c := b.channels[channelKey("p1", "b1")]
			id := strings.Repeat("a", 64)
			original := Command{Action: "element.press", Identity: c.documents[0].Identity, AttemptID: id, FingerprintVersion: 2, FingerprintSHA256: strings.Repeat("b", 64), BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash}
			c.attempts[id], c.unknown[id] = original, true
			read := Command{RequestID: "current-read", Action: "read", Identity: original.Identity}
			read.Identity.TabID++
			if mode == "independentInput" {
				read.Action = "element.press"
				read.AttemptID = strings.Repeat("c", 64)
			}
			c.pending[read.RequestID] = &pending{command: read, playwright: mode == "playwright", mutation: mode == "independentInput"}
			if mode == "playwright" {
				c.playwright = &playwrightExecution{command: read}
			}
			b.mu.Unlock()
			status, err := g.BrowserStatus(ctx, p)
			want := int32(1)
			unknown := 0
			if mode == "playwright" {
				want, unknown = 0, 1
			}
			if err != nil || queries.Load() != want || status.Channels[0].PendingCount != 1 || status.Channels[0].UnknownCount != unknown || inputs.Load() != 0 {
				t.Fatal("status crossed the existing owner or muted metadata-only reconciliation", err)
			}
			b.mu.Lock()
			c.playwright = nil
			delete(c.pending, read.RequestID)
			b.mu.Unlock()
			if mode == "playwright" {
				status, err = g.BrowserStatus(ctx, p)
				if err != nil || queries.Load() != 1 || status.Channels[0].UnknownCount != 0 || inputs.Load() != 0 {
					t.Fatal("drained Playwright owner prevented later receipt reconciliation", err)
				}
			}
		})
	}
}
