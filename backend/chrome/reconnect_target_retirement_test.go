package chrome

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

func TestReconnectUnknownTargetRetirementPreservesAuditAndRejectsChangedACK(t *testing.T) {
	for _, mode := range []string{"valid", "sameFence", "sameFenceWrongACK", "sameFenceWrongGeneration", "inactivePrivacy", "wrongLease", "wrongFingerprint", "wrongIdentity", "knownOutcome", "otherHazard", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, c, conn := setupFixture(t)
			b := g.broker
			var retainedPrivacy *credentialPrivacyState
			lease := Lease{ID: "original-lease", Generation: 1}
			row := ReconnectBinding{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7, FrameID: 0, DocumentID: "old-document", Generation: 1}, Fence: ReconnectFence{"old-broker", "old-channel", c.scopeHash}, AttemptID: strings.Repeat("d", 64), Fingerprint: strings.Repeat("e", 64), DispatchState: "unknown", ControlLease: &lease}
			if strings.HasPrefix(mode, "sameFence") {
				row.Fence = ReconnectFence{b.epoch, c.epoch, c.scopeHash}
			}
			finished := make(chan error, 1)
			b.mu.Lock()
			if mode == "inactivePrivacy" {
				retainedPrivacy = &credentialPrivacyState{active: false, published: true}
				c.privacy = retainedPrivacy
			}
			if mode != "legacy" {
				c.playwrightTargetRetirementVersion = 1
			}
			if mode == "otherHazard" {
				c.unknown["other-original"] = true
			}
			b.reconnectBindings = func(held context.Context, actual auth.Principal, _ ReconnectBindingScope, check func(context.Context) error, consume func([]ReconnectBinding) error) error {
				if actual.Namespace != p.Namespace {
					t.Error("snapshot actor changed")
				}
				e := check(held)
				if e == nil {
					e = consume([]ReconnectBinding{row})
				}
				finished <- e
				return e
			}
			b.mu.Unlock()
			q := reconnectBindingsRequest{"reconnectBindings", c.executorChallenge, strings.Repeat("a", 64), b.epoch, c.epoch, c.scopeHash, time.Now().Add(2 * time.Second).UnixMilli(), reconnectPendingFixture(c.scopeHash)}
			if strings.HasPrefix(mode, "sameFence") {
				q.Pending, _ = json.Marshal(map[string]any{"version": 1, "phase": "pending", "nonce": strings.Repeat("f", 64), "oldFence": row.Fence, "newFence": row.Fence, "history": []any{}})
			}
			wire, _ := json.Marshal(q)
			var request map[string]any
			_ = json.Unmarshal(wire, &request)
			if mode != "legacy" {
				request["targetRetirementAttempts"] = []string{row.AttemptID}
			}
			if e := WriteFrame(conn, request); e != nil {
				t.Fatal(e)
			}
			raw, e := ReadFrame(conn)
			if e != nil {
				t.Fatal(e)
			}
			var page struct {
				Type     string
				Bindings []ReconnectBinding
			}
			if json.Unmarshal(raw, &page) != nil || page.Type != "reconnectBindingsResult" || len(page.Bindings) != 1 || (page.Bindings[0].ControlLease != nil) != (mode != "legacy") {
				t.Fatal("negotiated lease metadata missing")
			}
			if e = WriteFrame(conn, map[string]any{"type": "reconnectBindingsDone", "requestId": q.RequestID, "complete": true}); e != nil {
				t.Fatal(e)
			}
			raw, e = ReadFrame(conn)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "legacy" {
				if !strings.Contains(string(raw), "reconnectBindingsCommitReady") {
					t.Fatal("legacy shape changed")
				}
			} else {
				var command Command
				if json.Unmarshal(raw, &command) != nil || command.Action != "executor.retire" || command.AttemptID != row.AttemptID || command.Identity != row.Identity || command.ControlLease == nil || *command.ControlLease != lease || command.FingerprintSHA256 != row.Fingerprint {
					t.Fatal("original tuple changed")
				}
				ack := Reply{RequestID: command.RequestID, AttemptID: row.AttemptID, Identity: row.Identity, ControlLease: &lease, FingerprintVersion: 2, FingerprintSHA256: row.Fingerprint, RetiredAuthorityQuiesced: true, DispatchState: "unknown", EffectState: "unknown"}
				switch mode {
				case "wrongLease", "sameFenceWrongACK":
					copied := lease
					copied.ID = "other"
					ack.ControlLease = &copied
				case "sameFenceWrongGeneration":
					copied := lease
					copied.Generation++
					ack.ControlLease = &copied
				case "wrongFingerprint":
					ack.FingerprintSHA256 = strings.Repeat("f", 64)
				case "wrongIdentity":
					ack.Identity.DocumentID = "other"
				case "knownOutcome":
					ack.DispatchState = "dispatched"
					ack.EffectState = "unverified"
				}
				if e = WriteFrame(conn, ack); e != nil {
					t.Fatal(e)
				}
				raw, e = ReadFrame(conn)
				if e != nil {
					t.Fatal(e)
				}
			}
			positive := mode == "valid" || mode == "sameFence" || mode == "legacy" || mode == "inactivePrivacy"
			if positive {
				if !strings.Contains(string(raw), "reconnectBindingsCommitReady") {
					t.Fatal("operational ACK did not unblock commit")
				}
				if e = WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": q.ExecutorChallenge, "mutationFingerprintVersion": 2}); e != nil {
					t.Fatal(e)
				}
			}
			select {
			case e = <-finished:
				if (e == nil) != positive {
					t.Fatal("wrong completion", mode, e)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("bounded reconnect did not finish")
			}
			b.mu.Lock()
			if mode == "valid" || mode == "sameFence" || mode == "inactivePrivacy" {
				if retainedPrivacy != nil && (c.privacy != retainedPrivacy || c.privacy.active) {
					t.Fatal("metadata recovery erased or activated old private state")
				}
				if !c.executorQualified || c.unknown[row.AttemptID] || c.receipts[row.AttemptID].DispatchState != "unknown" || c.receipts[row.AttemptID].EffectState != "unknown" {
					t.Fatal("retirement resolved business uncertainty")
				}
				original := Command{AttemptID: row.AttemptID, FingerprintVersion: 2, FingerprintSHA256: row.Fingerprint}
				receipt, err := b.mutationHistoryLocked(c, original)
				if err == nil || receipt == nil || receipt.DispatchState != "unknown" {
					t.Fatal("original attempt became replayable")
				}
				_, err = b.mutationHistoryLocked(c, Command{AttemptID: "fresh-unrelated", FingerprintVersion: 2, FingerprintSHA256: strings.Repeat("b", 64)})
				if err != nil {
					t.Fatal("dead target still blocks unrelated history admission", err)
				}
			} else if !positive {
				blocked := c.unknown[row.AttemptID]
				if mode == "otherHazard" {
					blocked = c.unknown["other-original"] && !c.unknown[row.AttemptID]
				}
				if c.executorQualified || !blocked || c.receipts[row.AttemptID].DispatchState != "unknown" {
					t.Fatal("invalid retirement removed original hazard or qualified input")
				}
			}
			b.mu.Unlock()
			if mode == "valid" {
				conn.Close()
				waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.conn == nil })
				b.mu.Lock()
				rearmed := c.unknown[row.AttemptID] && len(c.retiredTargets) == 0 && c.receipts[row.AttemptID].DispatchState == "unknown"
				b.mu.Unlock()
				if !rearmed {
					t.Fatal("connection loss reused stale target proof")
				}
			}
			_ = ctx
		})
	}
}

func TestRetireControlConsumesExactTargetDeathWithoutReplayingUnknown(t *testing.T) {
	for _, mode := range []string{"valid", "wrongClient", "wrongLease", "wrongEpoch", "wrongFingerprint", "otherHazard"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, c, _ := setupFixture(t)
			id := strings.Repeat("d", 64)
			lease := Lease{ID: "original-lease", Generation: 3}
			a := ControlAuthority{Owner: p.Namespace, ClientID: p.ClientID, BrokerEpoch: "old-broker", ChannelEpoch: "old-channel", ScopeHash: c.scopeHash, Lease: lease, Document: Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7, DocumentID: "dead-source", Generation: 1}}}
			command := Command{Identity: a.Document.Identity, AttemptID: id, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash, ControlLease: &lease, FingerprintVersion: 2, FingerprintSHA256: strings.Repeat("e", 64)}
			receipt := Reply{Identity: command.Identity, AttemptID: id, ControlLease: &lease, FingerprintVersion: 2, FingerprintSHA256: command.FingerprintSHA256, DispatchState: "unknown", EffectState: "unknown"}
			g.broker.mu.Lock()
			c.executorQualified = true
			c.attempts[id] = command
			c.receipts[id] = receipt
			c.retiredTargets = map[string]Command{id: command}
			if mode == "otherHazard" {
				c.unknown["other"] = true
			}
			if mode == "wrongFingerprint" {
				wrong := command
				wrong.FingerprintSHA256 = strings.Repeat("f", 64)
				c.retiredTargets[id] = wrong
			}
			g.broker.mu.Unlock()
			if mode == "wrongClient" {
				a.ClientID = "foreign"
			}
			if mode == "wrongLease" {
				a.Lease.Generation++
			}
			if mode == "wrongEpoch" {
				a.ChannelEpoch = "different"
			}
			retired, err := g.RetireControl(ctx, p, a)
			if mode == "valid" {
				if err != nil || !retired {
					t.Fatal("exact death proof rejected", err)
				}
			} else if err == nil || retired {
				t.Fatal("foreign/changed hazard proof accepted")
			}
			g.broker.mu.Lock()
			got := c.receipts[id]
			attempts := len(c.attempts)
			pending := len(c.pending)
			g.broker.mu.Unlock()
			before, _ := json.Marshal(receipt)
			after, _ := json.Marshal(got)
			if string(before) != string(after) || attempts != 1 || pending != 0 {
				t.Fatal("cleanup changed UNKNOWN audit or sent input")
			}
		})
	}
}
