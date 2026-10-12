package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
)

func liveTabInventoryFixture(t *testing.T, version int) (*Gateway, auth.Principal, context.Context, *channel, net.Conn) {
	t.Helper()
	p := principal(t, "live-tab-metadata")
	p.ClientID = "verified-metadata-client"
	grant := enrollment(p, "metadata-channel")
	grant.TrustScope = TrustScopeDesktop
	host := session.ProcessIdentity{PID: 20, UID: uint32(os.Getuid()), Executable: "/fixture/native-host", StartToken: "100:1"}
	parent := session.ProcessIdentity{PID: 10, UID: host.UID, Executable: "/fixture/Chrome", StartToken: "200:1"}
	trust := &nativepeer.ChromeProcessPolicy{ExpectedUID: host.UID, NativeHostExecutable: host.Executable, ChromeExecutable: parent.Executable, NativeHostRequirement: "native-host-pin", ChromeRequirement: "chrome-pin"}
	b, e := newBrokerWithPeer(Config{SocketPath: filepath.Join(trustScopeTestDirectory(t), "metadata.sock"), Grants: []Enrollment{grant}, ProcessTrust: trust}, map[string]string{channelKey(grant.ProfileChannel, grant.BrowserInstance): strings.Repeat("synthetic", 8)}, func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		return nativepeer.ChromeProcessEvidence{NativeHost: host, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, KernelPeerQualified: true}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close() })
	conn, e := net.Dial("unix", b.listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if e = WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "setupMetadataVersion": 1, "tabInventoryVersion": version, "profileChannel": grant.ProfileChannel, "browserInstance": grant.BrowserInstance, "extensionOrigin": grant.ExtensionOrigin, "credential": strings.Repeat("synthetic", 8), "trustScope": TrustScopeDesktop}); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadFrame(conn); e != nil {
		t.Fatal(e)
	}
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.setupAvailable })
	g, e := NewGateway(b, GatewayOptions{})
	if e != nil {
		t.Fatal(e)
	}
	return g, p, auth.WithPrincipal(context.Background(), p), c, conn
}

func TestFreshTabInventoryIndependentOfRendererJournalAndPrivateState(t *testing.T) {
	g, p, ctx, c, conn := liveTabInventoryFixture(t, 1)
	g.broker.mu.Lock()
	c.privateInspection = &credentialAdmissionPending{}
	c.privateFlow = &credentialFlow{}
	c.privacy = &credentialPrivacyState{}
	c.unknown["original-unknown"] = true
	c.lifecycleInhibited = true
	c.attentionCode = "storedFenceMismatch"
	g.broker.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		raw, e := ReadFrame(conn)
		if e != nil {
			done <- e
			return
		}
		var q map[string]any
		if e = json.Unmarshal(raw, &q); e != nil {
			done <- e
			return
		}
		if q["type"] != "tabInventory" || q["expectedOrigin"] != c.grant.Origins[0] || len(q) != 7 {
			done <- context.Canceled
			return
		}
		done <- WriteFrame(conn, tabInventoryReply{Type: "tabInventoryResult", RequestID: q["requestId"].(string), BrokerEpoch: q["brokerEpoch"].(string), ChannelEpoch: q["channelEpoch"].(string), ScopeHash: q["scopeHash"].(string), TabIDs: []int{7, 9}, Complete: true, Reason: "none"})
	}()
	started := time.Now()
	out, e := g.ListTabHandles(ctx, p, c.grant.Origins[0])
	t.Logf("fresh_metadata_socket_us=%d", time.Since(started).Microseconds())
	if e != nil || !out.Complete || len(out.Tabs) != 2 {
		t.Fatal("current authenticated metadata blocked by renderer/journal state", out, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	for i, id := range []int{7, 9} {
		want := (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: id}}).QualifiedTabID()
		if out.Tabs[i].Handle != want || out.Tabs[i].Origin != c.grant.Origins[0] {
			t.Fatal("routing identity changed")
		}
	}
	wire, _ := json.Marshal(out)
	if strings.Contains(string(wire), "documentId") || strings.Contains(string(wire), "title") || out.ObservedAt.IsZero() {
		t.Fatal("metadata shape/timestamp invalid")
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if c.executorQualified || c.inventoryComplete || len(c.documents) != 0 || !c.unknown["original-unknown"] || !c.lifecycleInhibited || c.privateFlow == nil || c.privateInspection == nil || c.privacy == nil || c.attentionCode != "storedFenceMismatch" {
		t.Fatal("metadata observation changed execution/private/journal state")
	}
}

func tabInventoryTestReply(q tabInventoryRequest) tabInventoryReply {
	return tabInventoryReply{Type: "tabInventoryResult", RequestID: q.RequestID, BrokerEpoch: q.BrokerEpoch, ChannelEpoch: q.ChannelEpoch, ScopeHash: q.ScopeHash, TabIDs: []int{7}, Complete: true, Reason: "none"}
}

func TestFreshTabInventoryRejectsMalformedAndStaleRepliesWithoutClosingTransport(t *testing.T) {
	for _, mode := range []string{"foreignRequest", "staleFence", "wrongScope", "duplicate", "zero", "outOfRange", "overLimit", "privateField", "nilIDs", "inconsistentFailure"} {
		t.Run(mode, func(t *testing.T) {
			g, p, base, c, conn := liveTabInventoryFixture(t, 1)
			ctx, cancel := context.WithTimeout(base, 65*time.Millisecond)
			defer cancel()
			go func() {
				raw, _ := ReadFrame(conn)
				var q tabInventoryRequest
				json.Unmarshal(raw, &q)
				r := tabInventoryTestReply(q)
				switch mode {
				case "foreignRequest":
					r.RequestID = strings.Repeat("a", 64)
				case "staleFence":
					r.ChannelEpoch = "old-channel"
				case "wrongScope":
					r.ScopeHash = strings.Repeat("a", 64)
				case "duplicate":
					r.TabIDs = []int{7, 7}
				case "zero":
					r.TabIDs = []int{0}
				case "outOfRange":
					r.TabIDs = []int{2147483648}
				case "overLimit":
					r.TabIDs = make([]int, 201)
					for i := range r.TabIDs {
						r.TabIDs[i] = i + 1
					}
				case "nilIDs":
					r.TabIDs = nil
				case "inconsistentFailure":
					r.Complete = false
					r.Reason = "permissionUnavailable"
				case "privateField":
					_ = WriteFrame(conn, map[string]any{"type": "tabInventoryResult", "requestId": q.RequestID, "brokerEpoch": q.BrokerEpoch, "channelEpoch": q.ChannelEpoch, "scopeHash": q.ScopeHash, "tabIds": []int{7}, "complete": true, "reason": "none", "title": "PRIVATE_CANARY"})
					return
				}
				_ = WriteFrame(conn, r)
			}()
			out, e := g.ListTabHandles(ctx, p, c.grant.Origins[0])
			if e == nil || out.Complete || len(out.Tabs) != 0 || out.Reason != "transportUnavailable" {
				t.Fatal("malformed reply published routing data", out, e)
			}
			raw, _ := json.Marshal(out)
			if strings.Contains(string(raw), "PRIVATE_CANARY") {
				t.Fatal("private metadata escaped")
			}
			g.broker.mu.Lock()
			alive := c.conn != nil && c.tabInventoryPending == nil && !g.broker.closed
			g.broker.mu.Unlock()
			if !alive {
				t.Fatal("malformed metadata closed transport or retained pending request")
			}
		})
	}
}

func TestFreshTabInventoryFiniteFailureTruncationAndSortedFreshIDs(t *testing.T) {
	for _, mode := range []string{"permissionUnavailable", "inventoryUnavailable", "authorityChanged", "inventoryLimit", "none"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, c, conn := liveTabInventoryFixture(t, 1)
			go func() {
				raw, _ := ReadFrame(conn)
				var q tabInventoryRequest
				json.Unmarshal(raw, &q)
				r := tabInventoryTestReply(q)
				r.Reason = mode
				r.Complete = mode == "none"
				if mode == "inventoryLimit" {
					r.TabIDs = make([]int, 200)
					for i := range r.TabIDs {
						r.TabIDs[i] = 200 - i
					}
				} else if mode == "none" {
					r.TabIDs = []int{9, 7}
				} else {
					r.TabIDs = []int{}
				}
				_ = WriteFrame(conn, r)
			}()
			out, e := g.ListTabHandles(ctx, p, c.grant.Origins[0])
			if e != nil || out.Reason != mode || out.Complete != (mode == "none") {
				t.Fatal(out, e)
			}
			expected := 0
			if mode == "none" {
				expected = 2
			}
			if mode == "inventoryLimit" {
				expected = 200
			}
			if len(out.Tabs) != expected {
				t.Fatal("failure/truncation produced wrong count", len(out.Tabs))
			}
			if expected > 0 {
				if out.ObservedAt.IsZero() {
					t.Fatal("fresh timestamp missing")
				}
				first := 7
				if mode == "inventoryLimit" {
					first = 1
				}
				want := (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: first}}).QualifiedTabID()
				if out.Tabs[0].Handle != want {
					t.Fatal("metadata IDs not sorted")
				}
			}
		})
	}
}

func TestFreshTabInventoryRequiresCurrentActorOriginAndSupportedChannel(t *testing.T) {
	for _, mode := range []string{"foreignActor", "foreignOrigin", "scopeRevoked", "unsupportedWorker", "processUnavailable", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			version := 1
			if mode == "unsupportedWorker" {
				version = 0
			}
			g, p, ctx, c, conn := liveTabInventoryFixture(t, version)
			origin := c.grant.Origins[0]
			if mode == "foreignActor" {
				p.ClientID = "foreign"
			} else if mode == "foreignOrigin" {
				origin = "https://foreign.test"
			} else if mode == "scopeRevoked" {
				g.broker.mu.Lock()
				c.scopeQualified = false
				g.broker.mu.Unlock()
			} else if mode == "processUnavailable" {
				g.broker.verifyPeer = func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
					return nativepeer.ChromeProcessEvidence{}, context.Canceled
				}
			} else if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			out, e := g.ListTabHandles(ctx, p, origin)
			if out.Complete || len(out.Tabs) != 0 {
				t.Fatal("unqualified actor/channel exposed metadata", out, e)
			}
			if mode == "foreignActor" && e == nil {
				t.Fatal("forged client accepted")
			}
			if mode == "unsupportedWorker" && out.Reason != "unsupportedWorker" {
				t.Fatal("unsupported protocol did not report finite reason", out)
			}

			conn.SetReadDeadline(time.Now().Add(15 * time.Millisecond))
			if _, e := ReadFrame(conn); e == nil {
				t.Fatal("unqualified metadata reached worker")
			}
		})
	}
}

func TestFreshTabInventoryRevalidatesProcessAfterReply(t *testing.T) {
	g, p, ctx, c, conn := liveTabInventoryFixture(t, 1)
	original := g.broker.verifyPeer
	var changed atomic.Bool
	g.broker.verifyPeer = func(ctx context.Context, conn *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		if changed.Load() {
			return nativepeer.ChromeProcessEvidence{}, context.Canceled
		}
		return original(ctx, conn)
	}
	go func() {
		raw, _ := ReadFrame(conn)
		var q tabInventoryRequest
		json.Unmarshal(raw, &q)
		changed.Store(true)
		_ = WriteFrame(conn, tabInventoryTestReply(q))
	}()
	out, e := g.ListTabHandles(ctx, p, c.grant.Origins[0])
	if e != nil || out.Complete || len(out.Tabs) != 0 || out.Reason != "authorityChanged" {
		t.Fatal("changed process published metadata", out, e)
	}
	g.broker.mu.Lock()
	alive := c.conn != nil
	g.broker.mu.Unlock()
	if !alive {
		t.Fatal("metadata verification closed connection")
	}
}

func TestFreshTabInventoryProductionJSThroughAuthenticatedSocket(t *testing.T) {
	g, p, ctx, c, conn := liveTabInventoryFixture(t, 1)
	g.broker.mu.Lock()
	c.attentionCode = "storedFenceMismatch"
	c.unknown["original-unknown"] = true
	c.lifecycleInhibited = true
	g.broker.mu.Unlock()
	finished := make(chan error, 1)
	go func() {
		request, e := ReadFrame(conn)
		if e != nil {
			finished <- e
			return
		}
		child := exec.CommandContext(ctx, "node", "testdata/tab_inventory_wire.cjs")
		child.Stdin = bytes.NewReader(request)
		reply, e := child.Output()
		if e != nil {
			finished <- e
			return
		}
		// Preserve production key order across the actual protocol boundary.
		finished <- WriteFrame(conn, json.RawMessage(reply))
	}()
	started := time.Now()
	out, e := g.ListTabHandles(ctx, p, c.grant.Origins[0])
	t.Logf("production_js_metadata_socket_ms=%d", time.Since(started).Milliseconds())
	if e != nil || !out.Complete || len(out.Tabs) != 2 || out.Reason != "none" {
		t.Fatal("production metadata wire failed", out, e)
	}
	if e = <-finished; e != nil {
		t.Fatal(e)
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if c.executorQualified || c.inventoryComplete || !c.unknown["original-unknown"] || !c.lifecycleInhibited || c.attentionCode != "storedFenceMismatch" {
		t.Fatal("metadata route altered qualification/history")
	}
}
