package chrome

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

type readFixture struct {
	publicReadDelay       atomic.Int64
	publicReadMarked      atomic.Int64
	lastValidationMarked  atomic.Bool
	publicReadMode        atomic.Value
	lastScope             atomic.Value
	workerConn            net.Conn
	valueReadVersion      atomic.Int64
	valueReadCountDelta   atomic.Int64
	valueReadCountMissing atomic.Bool
	g                     *Gateway
	p                     auth.Principal
	ctx                   context.Context
	generation            atomic.Uint64
	value                 atomic.Value
	reads                 atomic.Int64
	mutations             atomic.Int64
	wrongDocument         atomic.Bool
	rejectAcquire         atomic.Bool
	staleAcquires         atomic.Int64
	acquireCalls          atomic.Int64
	loseAcquire           atomic.Bool
}

func newReadFixture(t *testing.T) *readFixture {
	return newReadFixtureScope(t, TrustScopeProfile)
}

func newReadFixtureScope(t *testing.T, trustScope string) *readFixture {
	t.Helper()
	dir, err := os.MkdirTemp("/private/tmp", "read-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	p.ClientID = "verified-client"
	host := session.ProcessIdentity{PID: 20, UID: uint32(os.Getuid()), StartToken: "1790000000:2", Executable: "/fixture/native-host"}
	chrome := session.ProcessIdentity{PID: 10, UID: uint32(os.Getuid()), StartToken: "1790000000:1", Executable: "/fixture/Chrome"}
	peer := func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		return nativepeer.ChromeProcessEvidence{NativeHost: host, ChromeParent: chrome, Ancestors: []session.ProcessIdentity{chrome}, KernelPeerQualified: true}, nil
	}
	profileDirectory := dir
	if trustScope == TrustScopeDesktop {
		profileDirectory = ""
	}
	grant := Enrollment{TrustScope: trustScope, Principal: p, ProfileChannel: "p1", BrowserInstance: "b1", ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", Origins: []string{"https://fixture.test"}, ProfileDirectory: profileDirectory}
	credential := strings.Repeat("fixture", 8)
	b, err := newBrokerWithPeer(Config{SocketPath: filepath.Join(dir, "broker.sock"), Grants: []Enrollment{grant}}, map[string]string{channelKey("p1", "b1"): credential}, peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	conn, err := net.Dial("unix", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "profileChannel": "p1", "browserInstance": "b1", "extensionOrigin": grant.ExtensionOrigin, "credential": credential, "trustScope": trustScope, "profileDirectory": profileDirectory, "profileLaunchQualified": trustScope == TrustScopeProfile})
	raw, err := ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var ack map[string]any
	json.Unmarshal(raw, &ack)
	WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": ack["executorChallenge"]})
	doc := Document{Identity: Identity{ProfileChannel: "p1", BrowserInstance: "b1", TabID: 7, FrameID: 0, DocumentID: "doc1", Generation: 1}, Origin: "https://fixture.test", Title: "Fixture"}
	WriteFrame(conn, map[string]any{"type": "documents", "documents": []Document{doc}})
	waitControl(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.channels[channelKey("p1", "b1")].inventoryComplete
	})
	g, _ := NewGateway(b, GatewayOptions{})
	f := &readFixture{g: g, p: p, ctx: auth.WithPrincipal(context.Background(), p), workerConn: conn}
	f.publicReadMode.Store("ready")
	f.generation.Store(1)
	f.value.Store("independent-result")
	go func() {
		for {
			raw, err := ReadFrame(conn)
			if err != nil {
				return
			}
			var kind struct{ Type string }
			json.Unmarshal(raw, &kind)
			if kind.Type == "credentialScope" {
				var q credentialScopeRequest
				json.Unmarshal(raw, &q)
				f.lastScope.Store(q)
				mode := f.publicReadMode.Load().(string)
				proof := &credentialPublicDocument{Version: 1, Identity: doc.Identity, RouteSHA256: strings.Repeat("a", 64), Public: true}
				proof.Identity.Generation = f.generation.Load()
				reply := credentialScopeReply{Type: "credentialScopeResult", RequestID: q.RequestID, BrokerEpoch: q.BrokerEpoch, ChannelEpoch: q.ChannelEpoch, ScopeHash: q.ScopeHash, Ready: true, Reason: "none", PublicDocument: proof}
				switch mode {
				case "private":
					reply.Ready = false
					reply.Reason = "scopeTargetProtected"
					reply.PublicDocument = nil
				case "wrongDocument":
					proof.Identity.TabID++
				case "zeroGeneration":
					proof.Identity.Generation = 0
				case "foreignProfile":
					proof.Identity.ProfileChannel = "foreign"
				case "missingProof":
					reply.PublicDocument = nil
				case "wrongHash":
					proof.RouteSHA256 = "PRIVATE_CANARY"
				case "notPublic":
					proof.Public = false
				}
				if q.Mode != "publicRead" {
					reply.PublicDocument = nil
				}
				if WriteFrame(conn, reply) != nil {
					return
				}
				continue
			}
			var cmd Command
			if json.Unmarshal(raw, &cmd) != nil {
				return
			}
			if cmd.PublicRead {
				f.publicReadMarked.Add(1)
			}
			if cmd.Action == "executor.validate" {
				f.lastValidationMarked.Store(cmd.PublicRead)
			}
			reply := Reply{RequestID: cmd.RequestID, Identity: cmd.Identity, ControlLease: cmd.ControlLease}
			reply.Identity.Generation = f.generation.Load()
			switch cmd.Action {
			case "executor.validate":
				reply.Validated = true
			case "executor.acquire":
				f.acquireCalls.Add(1)
				if f.loseAcquire.Load() {
					continue
				}
				if f.staleAcquires.Load() > 0 {
					f.staleAcquires.Add(-1)
					id := cmd.Identity
					id.Generation = f.generation.Add(1)
					if WriteFrame(conn, map[string]any{"requestId": cmd.RequestID, "identity": id, "error": map[string]any{"code": "staleGeneration", "message": "DOM changed; observe the current generation before dispatch", "stage": "browser", "dispatchState": "notDispatched", "effectState": "none"}}) != nil {
						return
					}
					continue
				}
				reply.Validated = !f.rejectAcquire.Load()
			case "executor.retire":
				reply.RetiredAuthorityQuiesced = true
			case "element.press":
				f.mutations.Add(1)
				reply.AttemptID = cmd.AttemptID
				reply.DispatchState = "dispatched"
				reply.EffectState = "unverified"
			case "read":
				f.reads.Add(1)
				value := f.value.Load().(string)
				reply.Value = &value
				if version := f.valueReadVersion.Load(); version != 0 {
					reply.ValueReadVersion = int(version)
					if !f.valueReadCountMissing.Load() {
						count := len(value) + int(f.valueReadCountDelta.Load())
						reply.ValueReadBytes = &count
					}
				}
				if f.wrongDocument.Load() {
					reply.Identity.DocumentID = "replacement-document"
				}
			}
			if delay := f.publicReadDelay.Load(); delay > 0 {
				time.Sleep(time.Duration(delay) * time.Millisecond)
			}
			if WriteFrame(conn, reply) != nil {
				return
			}
		}
	}()
	return f
}
func readTarget() model.Selector {
	return model.Selector{Surface: model.Surface{Kind: "web", Origin: "https://fixture.test", TabID: "p1/b1/7"}, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "result"}, Exact: true}}
}
func TestPinnedReadKeepsOriginalDocumentAcrossLeaseRetirement(t *testing.T) {
	f := newReadFixture(t)
	a, err := f.g.AdmitControl(f.ctx, f.p, readTarget().Surface)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := f.g.PinControlRead(f.ctx, f.p, a)
	if err != nil {
		t.Fatal(err)
	}
	retired, err := f.g.RetireControl(f.ctx, f.p, a)
	if err != nil || !retired {
		t.Fatalf("retirement failed %v", err)
	}
	f.generation.Store(3)
	value, proof, err := f.g.ReadPinned(f.ctx, f.p, pin, readTarget(), "text", nil)
	if err != nil || value.String != "independent-result" || proof.RequestID == "" || proof.Document.DocumentID != "doc1" || proof.Document.Generation != 3 || proof.Owner != f.p.Namespace || proof.ClientID != f.p.ClientID || proof.StartedAt.IsZero() || proof.ReturnedAt.Before(proof.StartedAt) || f.reads.Load() != 1 {
		t.Fatalf("actual read proof lost pin: %+v %+v %v", value, proof, err)
	}
	if _, err := f.g.PinControlRead(f.ctx, f.p, a); err == nil {
		t.Fatal("retired control minted a fresh mutation read pin")
	}
}
func TestPinnedReadRejectsDocumentChannelActorAndProcessChanges(t *testing.T) {
	for _, name := range []string{"document", "origin", "frame", "scope", "allWebsites", "epoch", "process", "actor", "zero-pin", "foreign-target"} {
		t.Run(name, func(t *testing.T) {
			f := newReadFixture(t)
			pin, err := f.g.PinReadDocument(f.ctx, f.p, readTarget().Surface)
			if err != nil {
				t.Fatal(err)
			}
			target := readTarget()
			p := f.p
			ctx := f.ctx
			c := pin.channel
			f.g.broker.mu.Lock()
			switch name {
			case "document":
				c.documents[0].DocumentID = "new-document"
			case "origin":
				c.documents[0].Origin = "https://other.test"
			case "frame":
				c.documents[0].FrameID = 1
			case "allWebsites":
				c.grant.AllWebsites = true
				c.grant.Origins = nil
			case "scope":
				c.scopeHash = "new-scope"
			case "epoch":
				c.epoch = "new-channel"
			case "process":
				c.processEvidence.NativeHost.StartToken = "1790000000:3"
			case "actor":
				p.ClientID = "other-client"
				ctx = auth.WithPrincipal(ctx, p)
			case "zero-pin":
				pin = ReadBinding{}
			case "foreign-target":
				target.Surface.TabID = "p1/b1/8"
			}
			f.g.broker.mu.Unlock()
			value, proof, err := f.g.ReadPinned(ctx, p, pin, target, "text", nil)
			if err == nil || value.Kind != "" || proof.RequestID != "" || f.reads.Load() != 0 {
				t.Fatalf("stale pin emitted read/evidence: %+v %+v %v", value, proof, err)
			}
		})
	}
}
func TestPinnedReadPreservesProtectedAndCoveragePolicy(t *testing.T) {
	for _, test := range []struct {
		name, value, attribute string
		wrong                  bool
	}{{"redacted", "[redacted]", "value", false}, {"truncation", strings.Repeat("x", 256), "text", false}, {"unsupported", "value", "innerHTML", false}, {"mismatched-reply", "value", "name", true}} {
		t.Run(test.name, func(t *testing.T) {
			f := newReadFixture(t)
			pin, err := f.g.PinReadDocument(f.ctx, f.p, readTarget().Surface)
			if err != nil {
				t.Fatal(err)
			}
			f.value.Store(test.value)
			f.wrongDocument.Store(test.wrong)
			value, proof, err := f.g.ReadPinned(f.ctx, f.p, pin, readTarget(), test.attribute, nil)
			if err == nil || value.Kind != "" || proof.RequestID != "" {
				t.Fatalf("protected/incomplete read became proof %+v %+v %v", value, proof, err)
			}
		})
	}
}

func TestPinnedReadExactValueCompleteness(t *testing.T) {
	for _, tc := range []struct {
		name, value, attribute string
		version, delta         int64
		missing, accept        bool
	}{
		{name: "long Unicode whitespace", value: "  \n\t" + strings.Repeat("Zażółć 😀 ", 90) + "\n  ", attribute: "value", version: 1, accept: true},
		{name: "boundary256", value: strings.Repeat("x", 256), attribute: "value", version: 1, accept: true},
		{name: "max bytes", value: strings.Repeat("😀", 8192), attribute: "value", version: 1, accept: true},
		{name: "empty", value: "", attribute: "value", version: 1, accept: true},
		{name: "legacy prefix", value: strings.Repeat("x", 256), attribute: "value"},
		{name: "oversize", value: strings.Repeat("😀", 8192) + "x", attribute: "value", version: 1},
		{name: "byte count mismatch", value: "😀", attribute: "value", version: 1, delta: -2},
		{name: "missing count", value: "safe", attribute: "value", version: 1, missing: true},
		{name: "unknown version", value: "safe", attribute: "value", version: 2},
		{name: "text not broadened", value: strings.Repeat("x", 256), attribute: "text", version: 1},
		{name: "name not broadened", value: "safe", attribute: "name", version: 1},
		{name: "redacted", value: "[redacted]", attribute: "value", version: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReadFixture(t)
			pin, err := f.g.PinReadDocument(f.ctx, f.p, readTarget().Surface)
			if err != nil {
				t.Fatal(err)
			}
			f.value.Store(tc.value)
			f.valueReadVersion.Store(tc.version)
			f.valueReadCountDelta.Store(tc.delta)
			f.valueReadCountMissing.Store(tc.missing)
			got, proof, err := f.g.ReadPinned(f.ctx, f.p, pin, readTarget(), tc.attribute, nil)
			if tc.accept {
				if err != nil || got.String != tc.value || proof.RequestID == "" {
					t.Fatalf("complete read rejected: %v", err)
				}
			} else if err == nil || got.Kind != "" || proof.RequestID != "" {
				t.Fatal("incomplete value became proof")
			}
		})
	}
}
