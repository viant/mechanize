package chrome

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
)

func setupFixture(t *testing.T) (*Gateway, auth.Principal, context.Context, *channel, net.Conn) {
	t.Helper()
	p := principal(t, "setup-metadata-owner")
	p.ClientID = "verified-setup-client"
	grant := enrollment(p, "setup-channel")
	grant.TrustScope = TrustScopeDesktop
	host := session.ProcessIdentity{PID: 20, UID: uint32(os.Getuid()), Executable: "/fixture/native-host", StartToken: "100:1"}
	parent := session.ProcessIdentity{PID: 10, UID: host.UID, Executable: "/fixture/Chrome", StartToken: "200:1"}
	trust := &nativepeer.ChromeProcessPolicy{ExpectedUID: host.UID, NativeHostExecutable: host.Executable, ChromeExecutable: parent.Executable, NativeHostRequirement: "native-host-pin", ChromeRequirement: "chrome-pin"}
	broker, err := newBrokerWithPeer(Config{SocketPath: filepath.Join(trustScopeTestDirectory(t), "setup.sock"), Grants: []Enrollment{grant}, ProcessTrust: trust}, map[string]string{channelKey(grant.ProfileChannel, grant.BrowserInstance): strings.Repeat("synthetic", 8)}, func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		return nativepeer.ChromeProcessEvidence{NativeHost: host, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, KernelPeerQualified: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { broker.Close() })
	conn, err := net.Dial("unix", broker.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "setupMetadataVersion": 1, "profileChannel": grant.ProfileChannel, "browserInstance": grant.BrowserInstance, "extensionOrigin": grant.ExtensionOrigin, "credential": strings.Repeat("synthetic", 8), "trustScope": TrustScopeDesktop})
	if _, err = ReadFrame(conn); err != nil {
		t.Fatal(err)
	}
	c := broker.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	waitControl(t, func() bool { broker.mu.Lock(); defer broker.mu.Unlock(); return c.setupAvailable })
	g, _ := NewGateway(broker, GatewayOptions{})
	return g, p, auth.WithPrincipal(context.Background(), p), c, conn
}
func setupReply(r setupMetadataRequest) setupMetadataReply {
	return setupMetadataReply{Type: "setupMetadata", RequestID: r.RequestID, Nonce: r.Nonce, BrokerEpoch: r.BrokerEpoch, ChannelEpoch: r.ChannelEpoch, ScopeHash: r.ScopeHash, Metadata: SetupMetadata{Version: 1, ExtensionID: strings.Repeat("a", 32), ExtensionVersion: "0.1.0", StorageSHA256: strings.Repeat("b", 64), StorageScope: "extension-local-v1", StorageStable: true, NativeConnected: true}}
}
func TestSetupMetadataWorksWithoutExecutorAndPreservesUnknownBarriers(t *testing.T) {
	g, p, ctx, c, conn := setupFixture(t)
	g.broker.mu.Lock()
	c.unknown["retained-unknown"] = true
	c.lifecycleInhibited = true
	g.broker.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		raw, e := ReadFrame(conn)
		if e != nil {
			done <- e
			return
		}
		var request setupMetadataRequest
		e = json.Unmarshal(raw, &request)
		if e != nil {
			done <- e
			return
		}
		reply := setupReply(request)
		reply.Metadata.UnknownAttempts = 1
		reply.Metadata.LifecycleInhibited = true
		done <- WriteFrame(conn, reply)
	}()
	proof, err := g.SetupMetadata(ctx, p, c.grant.ProfileChannel, c.grant.BrowserInstance)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	receipt := proof.Metadata()
	if receipt.Metadata.ExtensionID != strings.Repeat("a", 32) || receipt.BrokerUnknown != 1 || receipt.Metadata.LoadedDirectoryAvailable || len(receipt.MissingEvidence) != 4 || !setupHash.MatchString(receipt.ReceiptSHA256) {
		t.Fatal("metadata/provenance limits lost")
	}
	if err = g.VerifySetupMetadata(ctx, p, proof); err != nil {
		t.Fatal(err)
	}
	g.broker.mu.Lock()
	if c.executorQualified || c.inventoryComplete || !c.unknown["retained-unknown"] || !c.lifecycleInhibited {
		t.Fatal("setup observation changed authority")
	}
	c.epoch = "changed"
	g.broker.mu.Unlock()
	if g.VerifySetupMetadata(ctx, p, proof) == nil {
		t.Fatal("stale setup proof retained")
	}
}
func TestSetupMetadataRejectsUncorrelatedOrExtraMetadata(t *testing.T) {
	for _, mode := range []string{"nonce", "extension", "scope", "directory", "unstable", "extra"} {
		t.Run(mode, func(t *testing.T) {
			g, p, base, c, conn := setupFixture(t)
			ctx, cancel := context.WithTimeout(base, 80*time.Millisecond)
			defer cancel()
			go func() {
				raw, e := ReadFrame(conn)
				if e != nil {
					return
				}
				var request setupMetadataRequest
				json.Unmarshal(raw, &request)
				reply := setupReply(request)
				switch mode {
				case "nonce":
					reply.Nonce = strings.Repeat("0", 64)
				case "extension":
					reply.Metadata.ExtensionID = strings.Repeat("c", 32)
				case "scope":
					reply.ScopeHash = strings.Repeat("0", 64)
				case "directory":
					reply.Metadata.LoadedDirectoryAvailable = true
				case "unstable":
					reply.Metadata.StorageStable = false
				case "extra":
					encoded, _ := json.Marshal(reply)
					var fields map[string]any
					json.Unmarshal(encoded, &fields)
					fields["privateValue"] = "synthetic-private"
					WriteFrame(conn, fields)
					return
				}
				WriteFrame(conn, reply)
			}()
			proof, err := g.SetupMetadata(ctx, p, c.grant.ProfileChannel, c.grant.BrowserInstance)
			if err == nil || proof.Metadata().ReceiptSHA256 != "" || strings.Contains(err.Error(), "synthetic-private") {
				t.Fatal("invalid metadata admitted")
			}
		})
	}
}
func TestSetupMetadataCannotBorrowAnotherOwnerOrClient(t *testing.T) {
	g, p, ctx, c, _ := setupFixture(t)
	other := principal(t, "other")
	other.ClientID = p.ClientID
	if _, err := g.SetupMetadata(auth.WithPrincipal(context.Background(), other), other, c.grant.ProfileChannel, c.grant.BrowserInstance); err == nil {
		t.Fatal("foreign owner admitted")
	}
	requested := p
	requested.ClientID = "other-client"
	if _, err := g.SetupMetadata(ctx, requested, c.grant.ProfileChannel, c.grant.BrowserInstance); err == nil {
		t.Fatal("client substitution admitted")
	}
}
