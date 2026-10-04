package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

func trustScopeTestDirectory(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/private/tmp", "chrome-scope-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestNormalizeChromeTrustScopeAndEnrollmentBounds(t *testing.T) {
	for input, want := range map[string]string{"": TrustScopeProfile, TrustScopeProfile: TrustScopeProfile, TrustScopeDesktop: TrustScopeDesktop} {
		if got, err := NormalizeTrustScope(input); err != nil || got != want {
			t.Fatalf("scope %q: %q %v", input, got, err)
		}
	}
	for _, input := range []string{"Desktop", " desktop", "all", "profile\x00"} {
		if _, err := NormalizeTrustScope(input); err == nil {
			t.Fatalf("scope accepted: %q", input)
		}
	}
	dir := trustScopeTestDirectory(t)
	p := principal(t, "owner")
	grant := enrollment(p, "scope-bound")
	grant.TrustScope = TrustScopeDesktop
	grant.ProfileDirectory = dir
	if b, err := newBroker(Config{SocketPath: filepath.Join(dir, "channel.sock"), FixtureEnrollment: true, Grants: []Enrollment{grant}}, map[string]string{channelKey(grant.ProfileChannel, grant.BrowserInstance): strings.Repeat("fixture", 8)}); err == nil {
		b.Close()
		t.Fatal("desktop enrollment claimed profile directory")
	}
	grant.TrustScope = "unknown"
	grant.ProfileDirectory = ""
	if b, err := newBroker(Config{SocketPath: filepath.Join(dir, "channel.sock"), FixtureEnrollment: true, Grants: []Enrollment{grant}}, map[string]string{channelKey(grant.ProfileChannel, grant.BrowserInstance): strings.Repeat("fixture", 8)}); err == nil {
		b.Close()
		t.Fatal("unsupported enrollment accepted")
	}
}

func TestChromeScopeHashBindsExplicitTrustScope(t *testing.T) {
	dir := trustScopeTestDirectory(t)
	p := principal(t, "hash-owner")
	hashes := map[string]string{}
	for i, scope := range []string{"", TrustScopeProfile, TrustScopeDesktop} {
		grant := enrollment(p, "hash-scope")
		grant.TrustScope = scope
		b, err := newBroker(Config{SocketPath: filepath.Join(dir, string(rune('a'+i))+".sock"), FixtureEnrollment: true, Grants: []Enrollment{grant}}, map[string]string{channelKey(grant.ProfileChannel, grant.BrowserInstance): strings.Repeat("fixture", 8)})
		if err != nil {
			t.Fatal(err)
		}
		hashes[scope] = b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)].scopeHash
		b.Close()
	}
	if hashes[""] != hashes[TrustScopeProfile] || hashes[TrustScopeDesktop] == hashes[TrustScopeProfile] {
		t.Fatal("scope hash lost legacy normalization or explicit desktop binding")
	}
}

func TestDesktopChromeHelloRequiresExplicitEnrollmentAndProcessProof(t *testing.T) {
	for _, scenario := range []string{"desktop", "profile_enrollment", "missing_scope", "profile_scope", "unknown_scope", "profile_directory", "profile_launch", "profile_claim", "fixture_claim", "wrong_credential", "kernel_unqualified", "missing_host", "missing_parent", "intermediary", "missing_birth", "verifier_error"} {
		t.Run(scenario, func(t *testing.T) {
			dir := trustScopeTestDirectory(t)
			p := principal(t, "owner")
			host := session.ProcessIdentity{PID: 20, UID: uint32(os.Getuid()), Executable: "/fixture/native-host", StartToken: "1790000000:1"}
			parent := session.ProcessIdentity{PID: 10, UID: uint32(os.Getuid()), Executable: "/fixture/Chrome", StartToken: "1790000000:2"}
			evidence := nativepeer.ChromeProcessEvidence{NativeHost: host, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, KernelPeerQualified: true, ProfileQualified: true, ExecutorQualified: true}
			grant := enrollment(p, "desktop-channel")
			grant.TrustScope = TrustScopeDesktop
			grant.ProfileDirectory = ""
			if scenario == "profile_enrollment" {
				grant.TrustScope = TrustScopeProfile
				grant.ProfileDirectory = dir
			}
			switch scenario {
			case "kernel_unqualified":
				evidence.KernelPeerQualified = false
			case "missing_host":
				evidence.NativeHost = session.ProcessIdentity{}
			case "missing_parent":
				evidence.ChromeParent = session.ProcessIdentity{}
			case "intermediary":
				evidence.Ancestors = append([]session.ProcessIdentity{host}, parent)
			case "missing_birth":
				evidence.ChromeParent.StartToken = ""
				evidence.Ancestors[0] = evidence.ChromeParent
			}
			check := func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
				if scenario == "verifier_error" {
					return evidence, errors.New("signature rejected")
				}
				return evidence, nil
			}
			credential := strings.Repeat("fixture", 8)
			b, err := newBrokerWithPeer(Config{SocketPath: filepath.Join(dir, "channel.sock"), Grants: []Enrollment{grant}}, map[string]string{channelKey(grant.ProfileChannel, grant.BrowserInstance): credential}, check)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			conn, err := net.Dial("unix", b.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			hello := map[string]any{"type": "hello", "protocolVersion": 1, "profileChannel": grant.ProfileChannel, "browserInstance": grant.BrowserInstance, "extensionOrigin": grant.ExtensionOrigin, "credential": credential, "trustScope": TrustScopeDesktop, "profileDirectory": "", "profileLaunchQualified": false, "scopeQualified": true, "executorQualified": true}
			switch scenario {
			case "missing_scope":
				delete(hello, "trustScope")
			case "profile_scope":
				hello["trustScope"] = TrustScopeProfile
			case "unknown_scope":
				hello["trustScope"] = "all"
			case "profile_directory":
				hello["profileDirectory"] = dir
			case "profile_launch":
				hello["profileLaunchQualified"] = true
			case "profile_claim":
				hello["profileQualified"] = true
			case "fixture_claim":
				hello["fixtureEnrollment"] = true
			case "wrong_credential":
				hello["credential"] = strings.Repeat("wrong", 12)
			}
			WriteFrame(conn, hello)
			raw, err := ReadFrame(conn)
			if scenario != "desktop" {
				if err == nil {
					t.Fatalf("unqualified desktop hello acknowledged: %s", raw)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var ack map[string]any
			if err = json.Unmarshal(raw, &ack); err != nil {
				t.Fatal(err)
			}
			if ack["type"] != "processQualified" || ack["trustScope"] != TrustScopeDesktop || ack["scopeQualified"] != true || ack["profileQualified"] != false || ack["executorQualified"] != false {
				t.Fatalf("desktop scope falsely claimed profile/executor: %+v", ack)
			}
			g, _ := NewGateway(b, GatewayOptions{})
			ctx := auth.WithPrincipal(context.Background(), p)
			trust, err := g.ChannelTrust(ctx, p)
			if err != nil || len(trust) != 1 || trust[0].TrustScope != TrustScopeDesktop || !trust[0].ScopeQualified || trust[0].ProfileQualified || trust[0].ExecutorQualified || trust[0].Evidence.ProfileQualified || trust[0].Evidence.ExecutorQualified {
				t.Fatalf("desktop status layers: %+v %v", trust, err)
			}
			// Caller-owned scope/executor claims cannot skip the connection-specific challenge.
			WriteFrame(conn, map[string]any{"type": "documents", "documents": []Document{{Identity: Identity{ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, TabID: 7, FrameID: 0, DocumentID: "root", Generation: 1}, Origin: grant.Origins[0]}}, "scopeQualified": true, "executorQualified": true})
			time.Sleep(time.Millisecond)
			b.mu.Lock()
			qualified := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)].inventoryComplete
			b.mu.Unlock()
			if qualified {
				t.Fatal("hello claims bypassed renderer preparation")
			}
		})
	}
}

func TestDesktopChromeAuthorityAndReadPinsRemainScopeBound(t *testing.T) {
	f := newReadFixtureScope(t, TrustScopeDesktop)
	admitted, err := f.g.AdmitControl(f.ctx, f.p, readTarget().Surface)
	if err != nil {
		t.Fatal(err)
	}
	if admitted.TrustScope != TrustScopeDesktop || !admitted.ScopeQualified || admitted.ProfileQualified {
		t.Fatalf("desktop authority fabricated profile: %+v", admitted)
	}
	pin, err := f.g.PinControlRead(f.ctx, f.p, admitted)
	if err != nil {
		t.Fatal(err)
	}
	if proof := pin.Identity(); proof.TrustScope != TrustScopeDesktop || !proof.ScopeQualified {
		t.Fatalf("read pin omitted scope: %+v", proof)
	}
	for _, change := range []string{"scope", "qualification", "profile_claim"} {
		forged := admitted
		switch change {
		case "scope":
			forged.TrustScope = TrustScopeProfile
		case "qualification":
			forged.ScopeQualified = false
		case "profile_claim":
			forged.ProfileQualified = true
		}
		if f.g.VerifyControl(f.ctx, f.p, forged) == nil {
			t.Fatalf("changed authority %s accepted", change)
		}
	}
	forgedPin := pin
	forgedPin.trustScope = TrustScopeProfile
	if _, _, err := f.g.ReadPinned(f.ctx, f.p, forgedPin, readTarget(), "text", nil); err == nil {
		t.Fatal("cross-scope read pin accepted")
	}
	if _, proof, err := f.g.ReadPinned(f.ctx, f.p, pin, readTarget(), "text", nil); err != nil || proof.TrustScope != TrustScopeDesktop || !proof.ScopeQualified {
		t.Fatalf("desktop protected read failed: %+v %v", proof, err)
	}
	before, err := f.g.Observe(f.ctx, f.p, readTarget().Surface)
	if err != nil {
		t.Fatal(err)
	}
	c := f.g.controlChannel(admitted)
	f.g.broker.mu.Lock()
	c.grant.TrustScope = TrustScopeProfile
	c.grant.ProfileDirectory = "/fixture/profile"
	c.profileQualified = true
	f.g.broker.mu.Unlock()
	if f.g.VerifyControl(f.ctx, f.p, admitted) == nil {
		t.Fatal("scope transition retained renderer authority")
	}
	if _, _, err := f.g.ReadPinned(f.ctx, f.p, pin, readTarget(), "text", nil); err == nil {
		t.Fatal("scope transition retained read pin")
	}
	delta, err := f.g.ObserveSince(f.ctx, f.p, readTarget().Surface, before.ID)
	if err != nil || !delta.Reset || delta.Epoch == before.Epoch {
		t.Fatalf("scope transition reused observation cache: %+v %v", delta, err)
	}
}

func TestDesktopFixtureCannotClaimProductionTrust(t *testing.T) {
	dir := trustScopeTestDirectory(t)
	p := principal(t, "fixture-owner")
	grant := enrollment(p, "desktop-fixture")
	grant.TrustScope = TrustScopeDesktop
	credential := strings.Repeat("fixture", 8)
	b, err := newBroker(Config{SocketPath: filepath.Join(dir, "channel.sock"), FixtureEnrollment: true, Grants: []Enrollment{grant}}, map[string]string{channelKey(grant.ProfileChannel, grant.BrowserInstance): credential})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	conn, err := net.Dial("unix", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "profileChannel": grant.ProfileChannel, "browserInstance": grant.BrowserInstance, "extensionOrigin": grant.ExtensionOrigin, "credential": credential, "fixtureEnrollment": true, "trustScope": TrustScopeDesktop})
	if _, err = ReadFrame(conn); err != nil {
		t.Fatal(err)
	}
	g, _ := NewGateway(b, GatewayOptions{})
	ctx := auth.WithPrincipal(context.Background(), p)
	status, err := g.ChannelTrust(ctx, p)
	if err != nil || len(status) != 1 || status[0].ScopeQualified || status[0].ProcessQualified || status[0].ProfileQualified || status[0].ExecutorQualified || !status[0].FixtureOnly {
		t.Fatalf("fixture promoted to production: %+v %v", status, err)
	}
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	b.mu.Lock()
	c.documents = []Document{{Identity: Identity{ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, TabID: 7, FrameID: 0, DocumentID: "root", Generation: 1}, Origin: grant.Origins[0]}}
	c.inventoryComplete = true
	b.mu.Unlock()
	if _, _, err = g.controlSnapshot(ctx, p, model.Surface{Kind: "web", Origin: grant.Origins[0]}); err == nil {
		t.Fatal("desktop fixture created production control")
	}
	if _, err = g.PinReadDocument(ctx, p, model.Surface{Kind: "web", Origin: grant.Origins[0]}); err == nil {
		t.Fatal("desktop fixture created production read proof")
	}
}

func TestDesktopChromeRetainsUnknownAndExecutorBarriers(t *testing.T) {
	f := newReadFixtureScope(t, TrustScopeDesktop)
	b := f.g.broker
	b.mu.Lock()
	c := b.channels[channelKey("p1", "b1")]
	c.unknown["unreconciled-attempt"] = true
	b.mu.Unlock()
	if _, _, err := f.g.controlSnapshot(f.ctx, f.p, readTarget().Surface); err == nil {
		t.Fatal("desktop scope skipped unknown-effect control barrier")
	}
	b.mu.Lock()
	delete(c.unknown, "unreconciled-attempt")
	c.executorQualified = false
	b.mu.Unlock()
	if _, _, err := f.g.controlSnapshot(f.ctx, f.p, readTarget().Surface); err == nil {
		t.Fatal("desktop scope skipped executor preparation")
	}
	if _, err := f.g.PinReadDocument(f.ctx, f.p, readTarget().Surface); err == nil {
		t.Fatal("desktop read bypassed executor preparation")
	}
}
