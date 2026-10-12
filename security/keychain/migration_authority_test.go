package keychain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

type migrationAuthorityVerifierFixture struct {
	principal auth.Principal
	calls     int
	err       error
}

func (v *migrationAuthorityVerifierFixture) Verify(ctx context.Context, raw string) (auth.Principal, error) {
	v.calls++
	if ctx.Err() != nil || raw != "synthetic-private-admin-credential" {
		return auth.Principal{}, errors.New("private verifier failure")
	}
	return v.principal, v.err
}
func migrationAuthoritySocket(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "mm-auth-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "auth.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return server, client
}
func migrationAuthorityFixture(t *testing.T, durations ...time.Duration) (*migrationNativeAuthority, *migrationAuthorityVerifierFixture, *net.UnixConn, context.Context) {
	t.Helper()
	server, client := migrationAuthoritySocket(t)
	p, _ := auth.NewPrincipal("fixture-issuer", "fixture-tenant", "fixture-admin", []string{"consent:admin"})
	p.ClientID = "fixture-console"
	verifier := &migrationAuthorityVerifierFixture{principal: p}
	duration := 2 * time.Second
	if len(durations) > 0 {
		duration = durations[0]
	}
	enrollment := migrationNativeEnrollment{parentRequirement: `identifier "com.viant.mechanize.consent" and cdhash H"` + strings.Repeat("a", 40) + `"`, namespace: p.Namespace, clientID: p.ClientID, deadline: time.Now().Add(duration)}
	authority, err := migrationNativeAuthorityWith(server, enrollment, verifier, func(*net.UnixConn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authority.close)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return authority, verifier, client, ctx
}
func sendMigrationCredential(t *testing.T, c *net.UnixConn) {
	t.Helper()
	if err := writeMigrationNativeCredential(c, []byte("synthetic-private-admin-credential")); err != nil {
		t.Fatal(err)
	}
}
func TestMigrationNativeAuthorityBindsPeerAdminActorAndDeadline(t *testing.T) {
	a, v, c, ctx := migrationAuthorityFixture(t)
	peers := 0
	a.peer = func(*net.UnixConn) error { peers++; return nil }
	sendMigrationCredential(t, c)
	human, err := a.authenticate(ctx, a.enrollment.parentRequirement)
	if err != nil || !auth.NativeHuman(human) {
		t.Fatal("authenticated console not admitted")
	}
	deadline, _ := human.Deadline()
	if !deadline.Equal(a.enrollment.deadline) {
		t.Fatal("trusted deadline not retained")
	}
	if peers != 3 || v.calls != 1 {
		t.Fatalf("peer/admin verification missing: %d/%d", peers, v.calls)
	}
	if _, err = a.workerAuthority(human); err != nil || peers != 6 || v.calls != 2 {
		t.Fatal("worker did not revalidate")
	}
	for _, out := range []string{fmt.Sprintf("%v %#v", a, a), func() string { b, _ := json.Marshal(a); return string(b) }()} {
		if strings.Contains(out, "synthetic-private") || strings.Contains(out, a.enrollment.namespace) {
			t.Fatal("private authority exposed")
		}
	}
}
func TestMigrationNativeAuthorityRefusesBeforeCredentialRead(t *testing.T) {
	for _, mode := range []string{"peer", "pin", "unbounded", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			a, v, _, ctx := migrationAuthorityFixture(t)
			pin := a.enrollment.parentRequirement
			switch mode {
			case "peer":
				a.peer = func(*net.UnixConn) error { return errors.New("private peer error") }
			case "pin":
				pin = strings.Replace(pin, "consent", "broker", 1)
			case "unbounded":
				ctx = context.Background()
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			start := time.Now()
			if _, err := a.authenticate(ctx, pin); err == nil {
				t.Fatal("untrusted admission")
			}
			if time.Since(start) > time.Second || v.calls != 0 {
				t.Fatal("read or verifier before peer admission")
			}
		})
	}
}
func TestMigrationNativeAuthorityRejectsCredentialAndIdentityChanges(t *testing.T) {
	for _, mode := range []string{"namespace", "client", "scope", "expired", "peer"} {
		t.Run(mode, func(t *testing.T) {
			a, v, c, ctx := migrationAuthorityFixture(t)
			sendMigrationCredential(t, c)
			if _, err := a.workerAuthority(ctx); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "namespace":
				p, _ := auth.NewPrincipal("fixture-issuer", "fixture-tenant", "other", []string{"consent:admin"})
				p.ClientID = v.principal.ClientID
				v.principal = p
			case "client":
				v.principal.ClientID = "other"
			case "scope":
				v.principal.Scopes = nil
			case "expired":
				v.err = errors.New("token expired private detail")
			case "peer":
				a.peer = func(*net.UnixConn) error { return errors.New("peer replaced") }
			}
			if _, err := a.workerAuthority(ctx); err != errMigrationUnavailable {
				t.Fatal("changed authority admitted or detail exposed")
			}
			if !a.closed || len(a.credential) != 0 {
				t.Fatal("failed authority retained credential")
			}
		})
	}
}
func TestMigrationNativeAuthorityCredentialFrameRejectsJSONAndCancellation(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		a, v, c, ctx := migrationAuthorityFixture(t)
		c.Write([]byte(`{"credential":"synthetic-private-admin-credential","nativeHuman":true}`))
		if _, err := a.workerAuthority(ctx); err != errMigrationUnavailable || v.calls != 0 {
			t.Fatal("generic JSON accepted")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		a, _, _, ctx := migrationAuthorityFixture(t)
		ctx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { _, err := a.workerAuthority(ctx); done <- err }()
		cancel()
		select {
		case err := <-done:
			if err != errMigrationUnavailable {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("credential read ignored cancellation")
		}
	})
}
func TestMigrationNativeAuthorityDrivesBootstrapAndWorkerWithoutWireAuthority(t *testing.T) {
	a, v, c, ctx := migrationAuthorityFixture(t)
	sendMigrationCredential(t, c)
	config := migrationWorkerConfig{options: migrationFixtureOptions(), session: strings.Repeat("b", 64), executorRequirement: `identifier "com.viant.mechanize.custody-migration" and cdhash H"` + strings.Repeat("c", 40) + `"`}
	loader, err := newMigrationBootstrapLoader(config, strings.Repeat("d", 64), a.enrollment.parentRequirement, a.authenticate)
	if err != nil {
		t.Fatal(err)
	}
	wire := migrationWorkerChannelFixture{}
	if err = writeMigrationBootstrap(&wire, config, strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	// The fixture channel reads from its input; use the serialized output as input.
	input := migrationWorkerChannel(wire.outputBytes())
	loaded, err := loader.load(ctx, input)
	if err != nil || loaded.options != config.options || v.calls != 2 {
		t.Fatal("verified bootstrap integration failed", err)
	}
	if _, err = a.workerAuthority(ctx); err != nil || v.calls != 3 {
		t.Fatal("post-bootstrap worker authority unavailable")
	}
}

func TestMigrationNativeAuthorityBoundsBlockedCredentialRead(t *testing.T) {
	a, v, _, ctx := migrationAuthorityFixture(t, 25*time.Millisecond)
	start := time.Now()
	if _, err := a.workerAuthority(ctx); err != errMigrationUnavailable {
		t.Fatal("deadline did not deny admission")
	}
	if time.Since(start) > time.Second || v.calls != 0 {
		t.Fatal("credential read exceeded trusted deadline")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed || len(a.credential) != 0 {
		t.Fatal("expired authority retained data")
	}
}

func TestMigrationNativeAuthorityConstructorRejectsNonConsoleDelegation(t *testing.T) {
	a, v, c, _ := migrationAuthorityFixture(t)
	for _, mode := range []string{"broker", "expired", "long", "namespace", "client"} {
		enrollment := a.enrollment
		switch mode {
		case "broker":
			enrollment.parentRequirement = strings.Replace(enrollment.parentRequirement, "consent", "broker", 1)
		case "expired":
			enrollment.deadline = time.Now().Add(-time.Second)
		case "long":
			enrollment.deadline = time.Now().Add(time.Hour)
		case "namespace":
			enrollment.namespace = "caller namespace"
		case "client":
			enrollment.clientID = ""
		}
		if _, err := migrationNativeAuthorityWith(c, enrollment, v, func(*net.UnixConn) error { return nil }); err != errMigrationUnavailable {
			t.Fatal("invalid trusted enrollment admitted", mode)
		}
	}
}
