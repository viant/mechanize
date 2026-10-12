package chrome

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestVisibilityUnknownRequiresAuthenticatedTerminalProof(t *testing.T) {
	for _, mode := range []string{"terminal", "pending", "missingReceipt", "foreignReply", "extraReply", "differentProcess", "untyped", "nonVisibility"} {
		t.Run(mode, func(t *testing.T) {
			g, _, base, c, conn := setupFixture(t)
			id := strings.Repeat("b", 64)
			g.broker.mu.Lock()
			original := c.processEvidence
			q := openOriginRequest{Type: "browser.activateTab", AttemptID: id, Origin: c.grant.Origins[0], TabID: 7, BrokerEpoch: g.broker.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash}
			c.unknown[id] = true
			c.visibilityUnknownVersion = 1
			c.visibilityUnknown = map[string]*visibilityUnknown{id: {request: q, original: original}}
			if mode == "differentProcess" {
				clone := *original
				clone.ChromeParent.StartToken = "replacement"
				c.visibilityUnknown[id].original = &clone
			}
			if mode == "untyped" {
				delete(c.visibilityUnknown, id)
			}
			if mode == "nonVisibility" {
				c.visibilityUnknown[id].request.Type = "browser.openOrigin"
			}
			g.broker.mu.Unlock()
			if mode != "differentProcess" && mode != "untyped" {
				go func() {
					raw, e := ReadFrame(conn)
					if e != nil {
						return
					}
					var r visibilityStatusRequest
					json.Unmarshal(raw, &r)
					reply := visibilityStatusReply{Type: "browser.activationStatusResult", RequestID: r.RequestID, AttemptID: r.AttemptID, BrokerEpoch: r.BrokerEpoch, ChannelEpoch: r.ChannelEpoch, ScopeHash: r.ScopeHash, Quiescent: mode != "pending" && mode != "missingReceipt"}
					if mode == "foreignReply" {
						reply.AttemptID = strings.Repeat("c", 64)
					}
					if mode == "extraReply" {
						data, _ := json.Marshal(reply)
						var value map[string]any
						json.Unmarshal(data, &value)
						value["private"] = "CANARY"
						WriteFrame(conn, value)
					} else {
						WriteFrame(conn, reply)
					}
				}()
			}
			ctx, cancel := context.WithTimeout(base, 100*time.Millisecond)
			defer cancel()
			_ = g.broker.qualifyVisibilityUnknown(ctx, c)
			g.broker.mu.Lock()
			defer g.broker.mu.Unlock()
			if domUnknownBlockedLocked(c) != (mode != "terminal") {
				t.Fatal("incorrect DOM classification", mode)
			}
			if !c.unknown[id] || openOriginIdle(c) {
				t.Fatal("original unknown or visibility guard lost")
			}
			if mode == "terminal" {
				if _, err := g.broker.mutationHistoryLocked(c, Command{Action: "element.press", AttemptID: id}); err == nil {
					t.Fatal("activation identity reused for renderer mutation")
				}
				c.unknown["renderer-input"] = true
				if !domUnknownBlockedLocked(c) {
					t.Fatal("renderer unknown exempted")
				}
				delete(c.unknown, "renderer-input")
				c.attempts[id] = Command{Action: "element.fill", AttemptID: id}
				if !domUnknownBlockedLocked(c) {
					t.Fatal("renderer identity inherited visibility proof")
				}
				delete(c.attempts, id)
				replacement := *c.processEvidence
				c.processEvidence = &replacement
				if !domUnknownBlockedLocked(c) {
					t.Fatal("process pointer replacement retained proof")
				}
			}
		})
	}
}

func TestVisibilityUnknownMissingJournalAfterRestartNeverQualifies(t *testing.T) {
	// Broker restart has no authenticated original request classification. A bare
	// retained UNKNOWN cannot acquire classification from a caller's action label.
	c := &channel{unknown: map[string]bool{"original": true}}
	if !domUnknownBlockedLocked(c) {
		t.Fatal("missing provenance exempted")
	}
}

func TestAuthenticatedActivationNegativeIsNotDowngradedByLaterFenceChange(t *testing.T) {
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
	go func() {
		raw, e := ReadFrame(conn)
		if e != nil {
			return
		}
		var q openOriginRequest
		json.Unmarshal(raw, &q)
		data, _ := json.Marshal(openOriginReply{Type: q.Type + "Result", RequestID: q.RequestID, AttemptID: q.AttemptID, BrokerEpoch: q.BrokerEpoch, ChannelEpoch: q.ChannelEpoch, ScopeHash: q.ScopeHash, DispatchState: "notDispatched", ErrorCode: "authorityChanged"})
		g.broker.mu.Lock()
		g.broker.acceptOpenOriginLocked(c, c.conn, data)
		c.epoch = "new-channel-after-negative"
		g.broker.mu.Unlock()
	}()
	result, e := g.ExecuteActivateTab(held, p, c.grant.Origins[0], handle, strings.Repeat("d", 64), func(context.Context) error { return nil })
	if e == nil || result.DispatchState != "notDispatched" {
		t.Fatal("authenticated no-input proof downgraded", result, e)
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if len(c.unknown) != 0 {
		t.Fatal("negative created uncertainty")
	}
}
