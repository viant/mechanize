package chrome

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
)

type lifecycleFixture struct {
	gateway   *Gateway
	principal auth.Principal
	ctx       context.Context
	channel   *channel
	commands  atomic.Int32
	badPeer   atomic.Bool
	badReply  atomic.Bool
	roots     []Identity
}

func newLifecycleFixture(t *testing.T, total int) *lifecycleFixture {
	t.Helper()
	dir, e := os.MkdirTemp("/private/tmp", "life-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p, _ := auth.NewPrincipal("fixture", "", "lifecycle-owner", []string{"desktop:control"})
	p.ClientID = "client"
	parent := session.ProcessIdentity{PID: 10, UID: uint32(os.Getuid()), StartToken: "100:1", Executable: "/fixture/chrome"}
	leaf := session.ProcessIdentity{PID: 20, UID: uint32(os.Getuid()), StartToken: "200:1", Executable: "/fixture/host"}
	f := &lifecycleFixture{principal: p, ctx: auth.WithPrincipal(context.Background(), p)}
	verify := func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		host := leaf
		if f.badPeer.Load() {
			host.StartToken = "200:2"
		}
		return nativepeer.ChromeProcessEvidence{NativeHost: host, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, KernelPeerQualified: true}, nil
	}
	grant := Enrollment{Principal: p, ProfileChannel: "p1", BrowserInstance: "b1", ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", Origins: []string{"https://fixture.test"}, ProfileDirectory: dir}
	cred := strings.Repeat("x", 48)
	b, e := newBrokerWithPeer(Config{SocketPath: filepath.Join(dir, "broker.sock"), Grants: []Enrollment{grant}}, map[string]string{channelKey("p1", "b1"): cred}, verify)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close() })
	conn, e := net.Dial("unix", b.listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { conn.Close() })
	WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "profileChannel": "p1", "browserInstance": "b1", "extensionOrigin": grant.ExtensionOrigin, "credential": cred, "profileDirectory": dir, "profileLaunchQualified": true})
	raw, e := ReadFrame(conn)
	if e != nil {
		t.Fatal(e)
	}
	var ack map[string]any
	json.Unmarshal(raw, &ack)
	WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": ack["executorChallenge"], "mutationFingerprintVersion": 2})
	identity := Identity{ProfileChannel: "p1", BrowserInstance: "b1", TabID: 7, FrameID: 0, DocumentID: "doc1", Generation: 1}
	f.roots = []Identity{identity}
	WriteFrame(conn, map[string]any{"type": "documents", "documents": []Document{{Identity: identity, Origin: "https://fixture.test", MutationFingerprintVersion: 2}}})
	waitControl(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.channels[channelKey("p1", "b1")].inventoryComplete
	})
	f.gateway, _ = NewGateway(b, GatewayOptions{})
	f.channel = b.channels[channelKey("p1", "b1")]
	go func() {
		for {
			raw, e := ReadFrame(conn)
			if e != nil {
				return
			}
			f.commands.Add(1)
			var wire struct {
				Command
				Type    string `json:"type"`
				GuardID string `json:"lifecycleGuardId"`
			}
			if json.Unmarshal(raw, &wire) != nil {
				return
			}
			if wire.Type != "lifecycle" || wire.GuardID == "" {
				return
			}
			i := wire.Identity
			if f.badReply.Load() {
				i.DocumentID = "foreign"
			}
			var response any
			switch wire.Action {
			case "executor.quiesce":
				response = map[string]any{"requestId": wire.RequestID, "identity": i, "quiescent": true}
			case "executor.retire":
				response = map[string]any{"requestId": wire.RequestID, "identity": i, "retiredAuthorityQuiesced": true, "controlLease": wire.ControlLease}
			case "executor.receipts":
				offset := int(wire.Args["offset"].(float64))
				limit := int(wire.Args["limit"].(float64))
				end := offset + limit
				if end > total {
					end = total
				}
				rows := make([]ReceiptExportRow, 0, end-offset)
				for n := offset; n < end; n++ {
					rows = append(rows, ReceiptExportRow{AttemptID: fmt.Sprintf("attempt-%d", n), FingerprintSHA256: strings.Repeat("a", 64), FingerprintVersion: 2, DispatchState: "dispatched", EffectState: "unverified"})
				}
				response = ReceiptExportPage{Version: 2, RequestID: wire.RequestID, Identity: i, Total: total, Revision: uint64(total), Offset: offset, NextOffset: end, Truncated: end < total, Receipts: rows, Readiness: ReceiptExportReadiness{Quiesced: true, RecordingState: "none"}}
			default:
				return
			}
			if WriteFrame(conn, response) != nil {
				return
			}
		}
	}()
	return f
}
func TestLifecycleReceiptGuardAuthenticatedExportAndPersistentInhibition(t *testing.T) {
	f := newLifecycleFixture(t, 65)
	g, e := f.gateway.BeginLifecycleReceiptExport(f.ctx, f.principal, "p1", "b1")
	if e != nil {
		t.Fatal(e)
	}
	inventory, e := g.Inventory(f.ctx, f.principal)
	if e != nil || inventory.GuardID == "" || len(inventory.Roots) != 1 {
		t.Fatal("inventory proof missing", inventory, e)
	}
	inventory.Roots[0].DocumentID = "changed"
	inventory, e = g.Inventory(f.ctx, f.principal)
	if e != nil || inventory.Roots[0].DocumentID != "doc1" {
		t.Fatal("inventory aliases privateauthority")
	}
	if _, e = f.gateway.broker.call(f.ctx, f.channel, Command{Action: "observe", Identity: f.roots[0]}, false); e == nil {
		t.Fatal("normalread bypassedinhibition")
	}
	if e = g.Quiesce(f.ctx, f.principal, f.roots[0]); e != nil {
		t.Fatal(e)
	}
	manifest, e := g.Collect(f.ctx, f.principal, f.roots[0])
	if e != nil || manifest.Version != 2 || len(manifest.Receipts) != 65 || f.commands.Load() != 3 {
		t.Fatal("bounded pagingfailed", e, len(manifest.Receipts), f.commands.Load())
	}
	g.Close()
	if _, e = g.Inventory(f.ctx, f.principal); e == nil {
		t.Fatal("expiredguard usable")
	}
	f.gateway.broker.mu.Lock()
	inhibited := f.channel.lifecycleInhibited && !f.channel.executorQualified
	f.gateway.broker.mu.Unlock()
	if !inhibited {
		t.Fatal("Close resumedchannel")
	}
	again, e := f.gateway.BeginLifecycleReceiptExport(f.ctx, f.principal, "p1", "b1")
	if e != nil {
		t.Fatal("sameowner cannotinspect retainedinhibitedfacts", e)
	}
	again.Close()
}
func TestLifecycleReceiptGuardRejectsForgedActorChangedFenceAndPeer(t *testing.T) {
	for _, mode := range []string{"missingActor", "foreignClient", "callerScope", "changedPeer", "changedEpoch", "changedScope", "replacement", "wrongDocument", "canceled", "badReply"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleFixture(t, 0)
			g, e := f.gateway.BeginLifecycleReceiptExport(f.ctx, f.principal, "p1", "b1")
			if e != nil {
				t.Fatal(e)
			}
			defer g.Close()
			ctx, p, i := f.ctx, f.principal, f.roots[0]
			switch mode {
			case "missingActor":
				ctx = context.Background()
			case "foreignClient":
				p.ClientID = "foreign"
				ctx = auth.WithPrincipal(ctx, p)
			case "callerScope":
				actual := p
				actual.Scopes = []string{"desktop:observe"}
				ctx = auth.WithPrincipal(ctx, actual)
			case "changedPeer":
				f.badPeer.Store(true)
			case "changedEpoch":
				f.gateway.broker.mu.Lock()
				f.channel.epoch = "changed"
				f.gateway.broker.mu.Unlock()
			case "changedScope":
				f.gateway.broker.mu.Lock()
				f.channel.scopeHash = strings.Repeat("b", 64)
				f.gateway.broker.mu.Unlock()
			case "replacement":
				f.gateway.broker.mu.Lock()
				clone := *f.channel
				f.gateway.broker.channels[channelKey("p1", "b1")] = &clone
				f.gateway.broker.mu.Unlock()
			case "wrongDocument":
				i.DocumentID = "foreign"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "badReply":
				f.badReply.Store(true)
			}
			manifest, e := g.Collect(ctx, p, i)
			if e == nil || len(manifest.Receipts) != 0 {
				t.Fatal("invalidauthority returned trustedmanifest", manifest, e)
			}
			if mode != "badReply" && f.commands.Load() != 0 {
				t.Fatal("invalidauthority sentRPC", f.commands.Load())
			}
		})
	}
}
func TestLifecycleReceiptBeginRejectsReplacementWhileWaitingLane(t *testing.T) {
	f := newLifecycleFixture(t, 0)
	b := f.gateway.broker
	b.lane <- struct{}{}
	done := make(chan error, 1)
	go func() {
		g, e := f.gateway.BeginLifecycleReceiptExport(f.ctx, f.principal, "p1", "b1")
		if g != nil {
			g.Close()
		}
		done <- e
	}()
	time.Sleep(10 * time.Millisecond)
	b.mu.Lock()
	clone := *f.channel
	b.channels[channelKey("p1", "b1")] = &clone
	b.mu.Unlock()
	<-b.lane
	if e := <-done; e == nil {
		t.Fatal("orphanchannel lifecycleauthority minted")
	}
}

func TestLifecycleReceiptInhibitionRejectsPreviouslyAdmittedNormalCall(t *testing.T) {
	f := newLifecycleFixture(t, 0)
	paused, resume := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := f.gateway.broker.call(f.ctx, f.channel, Command{Action: "observe", Identity: f.roots[0]}, false, func() error { close(paused); <-resume; return nil })
		done <- err
	}()
	<-paused
	guard, err := f.gateway.BeginLifecycleReceiptExport(f.ctx, f.principal, "p1", "b1")
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	close(resume)
	if err = <-done; err == nil || f.commands.Load() != 0 {
		t.Fatal("previouslyadmittednormalcommand bypassedfreeze", err, f.commands.Load())
	}
}
func TestLifecycleReceiptGuardRequiresIdleOwnedCompleteProductionChannel(t *testing.T) {
	for _, mode := range []string{"fixture", "pending", "unknown", "incomplete", "duplicateRoot", "tooManyRoots", "foreignNamespace", "noControl"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleFixture(t, 0)
			b := f.gateway.broker
			ctx, p := f.ctx, f.principal
			b.mu.Lock()
			switch mode {
			case "fixture":
				f.channel.fixtureOnly = true
			case "pending":
				f.channel.pending["old"] = &pending{}
			case "unknown":
				f.channel.unknown["old"] = true
			case "incomplete":
				f.channel.inventoryComplete = false
			case "duplicateRoot":
				f.channel.documents = append(f.channel.documents, f.channel.documents[0])
			case "tooManyRoots":
				base := f.channel.documents[0]
				for n := 1; n <= 64; n++ {
					d := base
					d.DocumentID = fmt.Sprintf("doc%d", n+1)
					d.TabID += n
					f.channel.documents = append(f.channel.documents, d)
				}
			case "foreignNamespace":
				p, _ = auth.NewPrincipal("fixture", "", "foreign", []string{"desktop:control"})
				p.ClientID = "client"
				ctx = auth.WithPrincipal(ctx, p)
			case "noControl":
				actual := p
				actual.Scopes = []string{"desktop:observe"}
				ctx = auth.WithPrincipal(ctx, actual)
			}
			b.mu.Unlock()
			guard, err := f.gateway.BeginLifecycleReceiptExport(ctx, p, "p1", "b1")
			if guard != nil {
				guard.Close()
			}
			if err == nil || f.commands.Load() != 0 {
				t.Fatal("unqualifiedlifecycleguardcreated", guard, err, f.commands.Load())
			}
		})
	}
}
