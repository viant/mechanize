package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestActivationBindingIsRequiredAndCommittedBeforeNativeWrite(t *testing.T) {
	for _, mode := range []string{"missing", "failed", "committed", "processChanged"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, c, conn := setupFixture(t)
			g.broker.mu.Lock()
			c.tabMetadataVersion = 1
			c.executorQualified = true
			g.broker.mu.Unlock()
			handle := (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7}}).QualifiedTabID()
			held, _, e := g.PrepareActivateTab(ctx, p, c.grant.Origins[0], handle)
			if e != nil {
				t.Fatal(e)
			}
			var committed atomic.Bool
			var callbacks int
			var commit func(context.Context, ActivationBinding) error
			if mode != "missing" {
				commit = func(_ context.Context, b ActivationBinding) error {
					callbacks++
					if b.Namespace != p.Namespace || b.ClientID != p.ClientID || b.ProfileChannel != c.grant.ProfileChannel || b.BrowserInstance != c.grant.BrowserInstance || b.TabID != 7 || b.Origin != c.grant.Origins[0] || b.ChromePID != 10 || b.ChromeStartToken != "200:1" || b.NativeHostPID != 20 || b.NativeHostStartToken != "100:1" || b.BrowserAttemptID != strings.Repeat("a", 64) || b.FingerprintVersion != 1 || !fingerprintV2Hash.MatchString(b.FingerprintSHA256) || b.BrokerEpoch != g.broker.epoch || b.ChannelEpoch != c.epoch || b.ScopeHash != c.scopeHash {
						t.Error("binding did not preserve trusted original identity")
					}
					if mode == "failed" {
						return errors.New("PRIVATE-CANARY")
					}
					if mode == "processChanged" {
						g.broker.mu.Lock()
						copy := *c.processEvidence
						copy.ChromeParent.StartToken = "201:1"
						c.processEvidence = &copy
						g.broker.mu.Unlock()
					}
					committed.Store(true)
					return nil
				}
			}
			if mode == "committed" {
				go func() {
					raw, e := ReadFrame(conn)
					if e != nil {
						return
					}
					if !committed.Load() {
						t.Error("native input written before binding commit")
					}
					var q openOriginRequest
					json.Unmarshal(raw, &q)
					WriteFrame(conn, openOriginReply{Type: q.Type + "Result", RequestID: q.RequestID, AttemptID: q.AttemptID, BrokerEpoch: q.BrokerEpoch, ChannelEpoch: q.ChannelEpoch, ScopeHash: q.ScopeHash, DispatchState: "dispatched", TabID: q.TabID, ErrorCode: "none"})
				}()
			}
			result, e := g.ExecuteActivateTabBound(held, p, c.grant.Origins[0], handle, strings.Repeat("a", 64), func(context.Context) error { return nil }, commit)
			if mode == "committed" {
				if e != nil || result.DispatchState != "dispatched" || callbacks != 1 {
					t.Fatal(result, e, callbacks)
				}
				return
			}
			if e == nil || result.DispatchState != "notDispatched" || strings.Contains(e.Error(), "CANARY") {
				t.Fatal("failed binding did not refuse before input", result, e)
			}
			conn.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
			if _, readErr := ReadFrame(conn); readErr == nil {
				t.Fatal("failed binding reached native Chrome")
			}
			g.broker.mu.Lock()
			unknown, pending := len(c.unknown), c.openOriginPending
			g.broker.mu.Unlock()
			if unknown != 0 || pending != nil {
				t.Fatal("failed persistence left uncertain authority")
			}
		})
	}
}
