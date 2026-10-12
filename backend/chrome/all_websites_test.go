package chrome

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAllWebsitesOriginAdmissionAndLegacyScope(t *testing.T) {
	all := Enrollment{AllWebsites: true}
	for _, origin := range []string{"https://example.test", "http://ordinary.test", "https://example.test:8443", "http://localhost:8080", "http://[::1]:8080"} {
		if !allowedOrigin(all, origin) {
			t.Errorf("ordinary origin rejected: %q", origin)
		}
	}
	for _, origin := range []string{"", "file:///tmp/a", "chrome://settings", "chrome-extension://abcdef", "https://user:pass@example.test", "https://example.test/", "https://example.test?x=1", "https://example.test#x", "https://*.test", "https://", "https://example.test\\evil", "data:text/html,x", "blob:https://example.test/id"} {
		if allowedOrigin(all, origin) {
			t.Errorf("unsafe origin accepted: %q", origin)
		}
	}
	if allowedOrigin(Enrollment{AllWebsites: true, Origins: []string{"https://example.test"}}, "https://example.test") {
		t.Fatal("ambiguous broad scope accepted")
	}
	if allowedOrigin(Enrollment{Origins: []string{"https://exact.test"}}, "https://other.test") {
		t.Fatal("legacy scope broadened")
	}
}
func TestAllWebsitesEnrollmentAndHashBinding(t *testing.T) {
	p := principal(t, "all-websites")
	exact := enrollment(p, "scope")
	b := fixtureBroker(t, exact)
	c := b.channels[channelKey(exact.ProfileChannel, exact.BrowserInstance)]
	raw, _ := json.Marshal([]any{exact.Principal.Namespace, exact.ProfileChannel, exact.BrowserInstance, exact.ExtensionOrigin, exact.Origins, exact.ProfileDirectory, c.grant.TrustScope})
	sum := sha256.Sum256(raw)
	if c.scopeHash != hex.EncodeToString(sum[:]) {
		t.Fatal("legacy scope hash changed")
	}
	all := exact
	all.AllWebsites = true
	all.Origins = nil
	broad := fixtureBroker(t, all)
	connectHost(t, broad, all)
	if broad.channels[channelKey(all.ProfileChannel, all.BrowserInstance)].scopeHash == c.scopeHash {
		t.Fatal("broad enrollment did not change hash")
	}
	status, err := broad.BrowserStatus(auth.WithPrincipal(context.Background(), p), p)
	if err != nil || len(status.Channels) != 1 || !status.Channels[0].AllWebsites {
		t.Fatalf("broad scope absent from status: %+v %v", status, err)
	}
	for _, grant := range []Enrollment{func() Enrollment { x := exact; x.AllWebsites = true; return x }(), func() Enrollment { x := exact; x.Origins = nil; return x }()} {
		dir, err := os.MkdirTemp("/tmp", "allweb-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		invalid, err := newBroker(Config{SocketPath: filepath.Join(dir, "s"), FixtureEnrollment: true, Grants: []Enrollment{grant}}, map[string]string{channelKey(grant.ProfileChannel, grant.BrowserInstance): strings.Repeat("x", 48)})
		if err == nil {
			invalid.Close()
			t.Fatal("ambiguous/empty scope accepted")
		}
	}
}
func TestAllWebsitesLifecycleSnapshotRejectsScopeChange(t *testing.T) {
	f := newLifecycleFixture(t, 1)
	guard, err := f.gateway.BeginLifecycleReceiptExport(f.ctx, f.principal, "p1", "b1")
	if err != nil {
		t.Fatal(err)
	}
	f.gateway.broker.mu.Lock()
	f.channel.grant.AllWebsites = true
	f.channel.grant.Origins = nil
	f.gateway.broker.mu.Unlock()
	if _, err = guard.Inventory(f.ctx, f.principal); err == nil {
		t.Fatal("scope change retained lifecycle authority")
	}
}

func TestAllWebsitesChangeInvalidatesPinnedControlWithoutDispatch(t *testing.T) {
	g, p, ctx, count := controlFixture(t)
	step := controlStep(t)
	a, err := g.AdmitControl(ctx, p, step.Target.Surface)
	if err != nil {
		t.Fatal(err)
	}
	c := g.controlChannel(a)
	g.broker.mu.Lock()
	c.grant.AllWebsites = true
	c.grant.Origins = nil
	g.broker.mu.Unlock()
	if _, err = g.ExecuteControl(ctx, p, step, nil, a); err == nil || count.Load() != 0 {
		t.Fatal("changed enrollment dispatched with old authority", err, count.Load())
	}
}
