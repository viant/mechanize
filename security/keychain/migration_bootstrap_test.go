package keychain

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

func migrationBootstrapFixture(t *testing.T) (*migrationBootstrapLoader, []byte) {
	t.Helper()
	worker, _, _ := migrationWorkerFixture(t)
	parent := `identifier "com.viant.mechanize.broker" and cdhash H"` + strings.Repeat("4", 40) + `"`
	loader, err := newMigrationBootstrapLoader(worker.config, strings.Repeat("5", 64), parent, func(ctx context.Context, _ string) (context.Context, error) { return ctx, nil })
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err = writeMigrationBootstrap(&wire, worker.config, loader.configDigest); err != nil {
		t.Fatal(err)
	}
	return loader, wire.Bytes()
}
func TestMigrationBootstrapExactFrozenConfigurationReturnsTrustedCopy(t *testing.T) {
	loader, _ := migrationBootstrapFixture(t)
	expected := loader.expected
	expected.expectedIdentity = bytes.Repeat([]byte{17}, 16384)
	var seen []string
	configured, err := newMigrationBootstrapLoader(expected, loader.configDigest, loader.parentRequirement, func(ctx context.Context, pin string) (context.Context, error) {
		seen = append(seen, pin)
		return ctx, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err = writeMigrationBootstrap(&wire, expected, loader.configDigest); err != nil {
		t.Fatal(err)
	}
	if wire.Len() > migrationWorkerFrameLimit+4 {
		t.Fatal("bootstrap exceeded bounded frame")
	}
	expected.expectedIdentity[0] = 99 // Constructor must retain a private copy.
	channel := migrationWorkerChannel(wire.Bytes())
	result, err := configured.load(migrationFixtureContext(t, true), channel)
	if err != nil || !reflect.DeepEqual(result, configured.expected) || result.expectedIdentity[0] != 17 || channel.isClosed() || len(seen) != 2 || seen[0] != loader.parentRequirement || seen[1] != loader.parentRequirement {
		t.Fatal("bootstrap did not bind trusted frozen metadata")
	}
	result.expectedIdentity[0] = 98
	if configured.expected.expectedIdentity[0] != 17 {
		t.Fatal("returned config aliased enrollment")
	}
	if _, err = configured.load(migrationFixtureContext(t, true), migrationWorkerChannel(wire.Bytes())); err != errMigrationUnavailable {
		t.Fatal("bootstrap session replayed")
	}
}
func TestMigrationBootstrapRequiresAuthorityBeforeAnyRead(t *testing.T) {
	for _, mode := range []string{"no-native-human", "error", "nil-authority", "unbounded", "cancelled", "extended-deadline"} {
		t.Run(mode, func(t *testing.T) {
			loader, wire := migrationBootstrapFixture(t)
			ctx := migrationFixtureContext(t, mode != "no-native-human")
			switch mode {
			case "error":
				loader.authority = func(context.Context, string) (context.Context, error) {
					return nil, errors.New("private-admin-credential-canary")
				}
			case "nil-authority":
				loader.authority = func(context.Context, string) (context.Context, error) { return nil, nil }
			case "unbounded":
				ctx = masterFixtureContext(t, true)
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "extended-deadline":
				loader.authority = func(context.Context, string) (context.Context, error) {
					extended, cancel := context.WithTimeout(masterFixtureContext(t, true), time.Hour)
					t.Cleanup(cancel)
					return extended, nil
				}
			}
			channel := migrationWorkerChannel(wire)
			_, err := loader.load(ctx, channel)
			if err != errMigrationUnavailable || channel.readCount() != 0 || !channel.isClosed() {
				t.Fatal("unauthenticated bootstrap read input")
			}
		})
	}
}
func TestMigrationBootstrapAuthorityRecheckedAfterDecodeAndCannotSwitchActor(t *testing.T) {
	for _, mode := range []string{"namespace", "client", "revoked", "cancelled", "longer-deadline"} {
		t.Run(mode, func(t *testing.T) {
			loader, wire := migrationBootstrapFixture(t)
			ctx, cancel := context.WithCancel(migrationFixtureContext(t, true))
			defer cancel()
			calls := 0
			loader.authority = func(current context.Context, pin string) (context.Context, error) {
				calls++
				if pin != loader.parentRequirement {
					t.Fatal("authority saw untrusted parent pin")
				}
				if calls == 1 {
					return current, nil
				}
				switch mode {
				case "revoked":
					return nil, errors.New("private-revoked-admin-canary")
				case "cancelled":
					cancel()
					return current, nil
				case "longer-deadline":
					later, stop := context.WithTimeout(masterFixtureContext(t, true), time.Hour)
					t.Cleanup(stop)
					return later, nil
				}
				principal, err := auth.FromContext(current)
				if err != nil {
					return nil, err
				}
				if mode == "namespace" {
					different, err := auth.NewPrincipal("fixture", "", "different-bootstrap-admin", []string{"consent:admin"})
					if err != nil {
						return nil, err
					}
					different.ClientID = principal.ClientID
					principal = different
				} else {
					principal.ClientID = "different-verified-parent"
				}
				return auth.WithNativeHuman(auth.WithPrincipal(current, principal))
			}
			channel := migrationWorkerChannel(wire)
			result, err := loader.load(ctx, channel)
			if err != errMigrationUnavailable || calls != 2 || !channel.isClosed() || result.session != "" {
				t.Fatal("changed bootstrap authority accepted")
			}
		})
	}
}
func TestMigrationBootstrapRejectsEveryChangedFrozenField(t *testing.T) {
	changes := []func(*migrationBootstrapFrame){
		func(f *migrationBootstrapFrame) { f.Version = 2 }, func(f *migrationBootstrapFrame) { f.Operation = "prepare" },
		func(f *migrationBootstrapFrame) { f.Session = strings.Repeat("b", 64) }, func(f *migrationBootstrapFrame) { f.ConfigSHA256 = strings.Repeat("6", 64) },
		func(f *migrationBootstrapFrame) { f.CanonicalExecutable = "/private/selected-by-wire" }, func(f *migrationBootstrapFrame) { f.OldRequirement = f.NewRequirement },
		func(f *migrationBootstrapFrame) { f.NewRequirement = f.OldRequirement }, func(f *migrationBootstrapFrame) { f.Alias = "another-enrolled-alias" },
		func(f *migrationBootstrapFrame) { f.Service = "another-service" }, func(f *migrationBootstrapFrame) { f.Account = "another-account" },
		func(f *migrationBootstrapFrame) { f.WorkerRequirement = f.NewRequirement }, func(f *migrationBootstrapFrame) { f.ExpectedIdentity = []byte("another-opaque-reference") },
	}
	for _, change := range changes {
		loader, _ := migrationBootstrapFixture(t)
		frame := migrationBootstrapWire(loader.expected, loader.configDigest)
		change(&frame)
		data, _ := json.Marshal(frame)
		channel := migrationWorkerChannel(migrationWorkerRawFrame(data))
		_, err := loader.load(migrationFixtureContext(t, true), channel)
		if err != errMigrationUnavailable || !channel.isClosed() {
			t.Fatal("wire changed trusted bootstrap selection")
		}
	}
}
func TestMigrationBootstrapRejectsDuplicateExtraSecretAndTrustClaims(t *testing.T) {
	loader, _ := migrationBootstrapFixture(t)
	valid, _ := json.Marshal(migrationBootstrapWire(loader.expected, loader.configDigest))
	bad := [][]byte{nil, []byte("{}"), append(bytes.Clone(valid), []byte("{}")...), append([]byte(" "), valid...),
		[]byte(strings.Replace(string(valid), `"version":1`, `"version":1,"version":1`, 1))}
	for _, name := range []string{"password", "key", "value", "credential", "policy", "approved", "permission", "parentRole", "parentRequirement", "role", "namespace", "clientId", "principal", "scopes", "nativeHuman", "pid", "uid"} {
		bad = append(bad, []byte(strings.Replace(string(valid), `"version":1`, `"version":1,"`+name+`":"private-wire-canary"`, 1)))
	}
	for _, data := range bad {
		fresh, _ := migrationBootstrapFixture(t)
		calls := 0
		fresh.authority = func(ctx context.Context, _ string) (context.Context, error) { calls++; return ctx, nil }
		channel := migrationWorkerChannel(migrationWorkerRawFrame(data))
		_, err := fresh.load(migrationFixtureContext(t, true), channel)
		if err != errMigrationUnavailable || !channel.isClosed() || calls != 1 {
			t.Fatal("malformed/secret/trust field decoded")
		}
	}
}
func TestMigrationBootstrapRejectsHugeTruncatedAndTrailingFrames(t *testing.T) {
	var huge [4]byte
	binary.BigEndian.PutUint32(huge[:], migrationWorkerFrameLimit+1)
	for _, data := range [][]byte{huge[:], {0, 0, 0}, {0, 0, 0, 10, 'x'}} {
		loader, _ := migrationBootstrapFixture(t)
		channel := migrationWorkerChannel(data)
		if _, err := loader.load(migrationFixtureContext(t, true), channel); err != errMigrationUnavailable || !channel.isClosed() {
			t.Fatal("unbounded/truncated frame accepted")
		}
	}
}
func TestMigrationBootstrapKeepsFollowingWorkerFrameForAuthenticatedWorker(t *testing.T) {
	loader, wire := migrationBootstrapFixture(t)
	worker, _, _ := migrationWorkerFixture(t)
	request := migrationWorkerReq(worker, 1, "prepare")
	var following bytes.Buffer
	if err := writeMigrationWorkerRequest(&following, request); err != nil {
		t.Fatal(err)
	}
	channel := migrationWorkerChannel(append(wire, following.Bytes()...))
	if _, err := loader.load(migrationFixtureContext(t, true), channel); err != nil {
		t.Fatal(err)
	}
	decoded, err := readMigrationWorkerRequest(channel)
	if err != nil || decoded != request {
		t.Fatal("bootstrap consumed worker request bytes")
	}
}
func TestMigrationBootstrapShortAuthorityDeadlineClosesBlockedRead(t *testing.T) {
	loader, _ := migrationBootstrapFixture(t)
	parent := migrationFixtureContext(t, true)
	authority, cancel := context.WithTimeout(parent, 80*time.Millisecond)
	defer cancel()
	loader.authority = func(context.Context, string) (context.Context, error) { return authority, nil }
	server, client := net.Pipe()
	defer client.Close()
	observed := &migrationReadObserved{Conn: server, entered: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := loader.load(parent, observed); done <- err }()
	select {
	case <-observed.entered:
	case <-time.After(time.Second):
		t.Fatal("bootstrap did not start bounded read")
	}
	select {
	case err := <-done:
		if err != errMigrationUnavailable {
			t.Fatal("expired authority accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("short authority deadline failed to close read")
	}
}
func TestMigrationBootstrapParentCancellationClosesBlockedRead(t *testing.T) {
	loader, _ := migrationBootstrapFixture(t)
	ctx, cancel := context.WithCancel(migrationFixtureContext(t, true))
	defer cancel()
	server, client := net.Pipe()
	defer client.Close()
	observed := &migrationReadObserved{Conn: server, entered: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := loader.load(ctx, observed); done <- err }()
	select {
	case <-observed.entered:
	case <-time.After(time.Second):
		t.Fatal("bootstrap did not start read")
	}
	cancel()
	select {
	case err := <-done:
		if err != errMigrationUnavailable {
			t.Fatal("cancelled bootstrap accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation failed to close bootstrap")
	}
}
func TestMigrationBootstrapRefusesInvalidTrustedEnrollmentWithoutReading(t *testing.T) {
	loader, _ := migrationBootstrapFixture(t)
	for _, pin := range []string{"anchor apple", loader.parentRequirement + " or true", `identifier "other.role" and cdhash H"` + strings.Repeat("1", 40) + `"`} {
		if _, err := newMigrationBootstrapLoader(loader.expected, loader.configDigest, pin, loader.authority); err != errMigrationUnavailable {
			t.Fatal("broad parent enrollment accepted")
		}
	}
	if _, err := newMigrationBootstrapLoader(loader.expected, "caller-digest", loader.parentRequirement, loader.authority); err != errMigrationUnavailable {
		t.Fatal("unbounded digest accepted")
	}
	if _, err := newMigrationBootstrapLoader(loader.expected, loader.configDigest, loader.parentRequirement, nil); err != errMigrationUnavailable {
		t.Fatal("missing peer/admin authority accepted")
	}
	for _, alter := range []func(*migrationWorkerConfig){func(c *migrationWorkerConfig) { c.session = "nonce" }, func(c *migrationWorkerConfig) { c.options.canonicalExecutable = "relative" }, func(c *migrationWorkerConfig) { c.expectedIdentity = make([]byte, 16385) }, func(c *migrationWorkerConfig) { c.options.item.Account = string([]byte{0xff}) }} {
		config := loader.expected
		alter(&config)
		if _, err := newMigrationBootstrapLoader(config, loader.configDigest, loader.parentRequirement, loader.authority); err != errMigrationUnavailable {
			t.Fatal("invalid frozen config accepted")
		}
	}
}
func TestMigrationBootstrapPrivateErrorsAndEnrollmentDoNotAppearInPublicFormatting(t *testing.T) {
	loader, wire := migrationBootstrapFixture(t)
	loader.authority = func(context.Context, string) (context.Context, error) {
		return nil, errors.New("private-admin-password-error-canary")
	}
	channel := migrationWorkerChannel(wire)
	_, err := loader.load(migrationFixtureContext(t, true), channel)
	encoded, _ := json.Marshal(loader)
	text := fmt.Sprintf("%v %+v %#v %v", loader, loader, loader, err) + string(encoded)
	if strings.Contains(text, "private-admin-password-error-canary") || strings.Contains(text, loader.expected.options.item.Account) || strings.Contains(text, loader.expected.options.canonicalExecutable) || len(channel.outputBytes()) != 0 {
		t.Fatal("bootstrap disclosed private state or raw errors")
	}
}
