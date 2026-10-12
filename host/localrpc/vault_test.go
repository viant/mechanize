package localrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/vault"
)

type socketFixtureKeys struct{}

func (socketFixtureKeys) Resolve(context.Context, string) ([]byte, error) {
	return bytes.Repeat([]byte{91}, 32), nil
}

type socketFixtureProtection struct {
	deny           bool
	denyEnrollment bool
	calls          atomic.Int32
}

func (p *socketFixtureProtection) WithEntry(ctx context.Context, target vault.Target, action func() error) error {
	p.calls.Add(1)
	if !auth.NativeHuman(ctx) {
		return errors.New("unverified fixture actor")
	}
	if p.deny {
		return errors.New("synthetic-private-error-canary")
	}
	return action()
}
func vaultSocketFixture(t *testing.T, enabled bool, guard *socketFixtureProtection) (*net.UnixConn, *vault.Store, auth.Principal, string) {
	t.Helper()
	dir, err := os.MkdirTemp("/private/tmp", "mc-vault-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0700)
	p, _ := auth.NewPrincipal("fixture", "", "native-human", []string{"consent:admin"})
	store, err := vault.NewStore(filepath.Join(dir, "vault"), "fixture-v1", &vault.Cipher{Keys: socketFixtureKeys{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	var service *vault.NativeInputService
	if enabled {
		service, err = vault.NewNativeInputService(store, guard)
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server, err := New(ctx, Options{SocketPath: filepath.Join(dir, "ui.sock"), Verifier: fixtureVerifier{p}, VerifyPeer: func(*net.UnixConn) error { return nil }, VaultInput: service, AuthorizeVault: func(_ context.Context, actor auth.Principal) error {
		if actor.Namespace != p.Namespace || guard.denyEnrollment {
			return auth.ErrUnauthorized
		}
		return nil
	}, Handle: func(context.Context, string, json.RawMessage) (any, error) {
		t.Error("secret reached generic JSON handler")
		return nil, errors.New("unexpected handler")
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(dir, "ui.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	hello := send(t, c, map[string]any{"jsonrpc": "2.0", "id": "1", "method": "hello", "params": map[string]any{"protocolVersion": 1, "credential": "fixture-enrollment", "clientBundleID": "com.viant.mechanize.consent"}})
	return c, store, p, hello.Result.(map[string]any)["sessionID"].(string)
}
func vaultSocketSend(t *testing.T, c *net.UnixConn, session string, extra map[string]any) response {
	t.Helper()
	params := map[string]any{"sessionID": session, "origin": "https://example.test", "accountAlias": "fixture-account"}
	for key, value := range extra {
		params[key] = value
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "2", "method": "vault.create", "params": params})
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(body)))
	c.Write(append(prefix[:], body...))
	first := vaultSocketRead(t, c)
	if first.Error != nil {
		return first
	}
	result, ok := first.Result.(map[string]any)
	if !ok || result["nativeInputReady"] != true {
		t.Fatal("native admission missing")
	}
	frame := []byte{'M', 'V', 'L', 'T', 0, 0, 0, 1}
	pair := []byte("socket-fixture-user")
	password := []byte("socket-fixture-password")
	var lengths [8]byte
	binary.BigEndian.PutUint32(lengths[:4], uint32(len(pair)))
	binary.BigEndian.PutUint32(lengths[4:], uint32(len(password)))
	frame = append(frame, lengths[:]...)
	frame = append(frame, pair...)
	frame = append(frame, password...)
	c.Write(frame)
	c.CloseWrite()
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size > MaxFrameBytes {
		t.Fatal("response bound")
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(c, raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, pair) || bytes.Contains(raw, password) || bytes.Contains(raw, []byte("canary")) {
		t.Fatal("secret/error in response")
	}
	var r response
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}
func vaultSocketRead(t *testing.T, c *net.UnixConn) response {
	t.Helper()
	var prefix [4]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size > MaxFrameBytes {
		t.Fatal("response bound")
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(c, raw); err != nil {
		t.Fatal(err)
	}
	var r response
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestVaultSocketBinaryBodyReachesOnlyProtectedNativeStore(t *testing.T) {
	guard := &socketFixtureProtection{}
	c, store, p, session := vaultSocketFixture(t, true, guard)
	r := vaultSocketSend(t, c, session, nil)
	if r.Error != nil || guard.calls.Load() != 1 {
		t.Fatal("protected native create failed")
	}
	data, _ := json.Marshal(r.Result)
	if !strings.Contains(string(data), "mechanize-vault://credential/") {
		t.Fatal("opaque reference missing")
	}
	if _, err := store.Metadata(auth.WithPrincipal(context.Background(), p), vault.Target{Origin: "https://example.test", Account: "fixture-account"}); err != nil {
		t.Fatal("encrypted entry missing")
	}
}
func TestVaultSocketDisabledProtectionAndUnknownMetadataNeverWrite(t *testing.T) {
	for _, mode := range []string{"disabled", "protection", "extra-field", "enrollment"} {
		t.Run(mode, func(t *testing.T) {
			guard := &socketFixtureProtection{deny: mode == "protection", denyEnrollment: mode == "enrollment"}
			c, store, p, session := vaultSocketFixture(t, mode != "disabled", guard)
			var extra map[string]any
			if mode == "extra-field" {
				extra = map[string]any{"password": "synthetic-must-not-be-JSON"}
			}
			r := vaultSocketSend(t, c, session, extra)
			if r.Error == nil {
				t.Fatal("unsafe channel accepted")
			}
			if _, err := store.Metadata(auth.WithPrincipal(context.Background(), p), vault.Target{Origin: "https://example.test", Account: "fixture-account"}); !errors.Is(err, vault.ErrMissing) {
				t.Fatal("entry written despite refusal")
			}
		})
	}
}

func TestVaultReadyReaderRechecksAuthorityBeforeRequestingBytes(t *testing.T) {
	// A revoked code/credential check fails before admission output or socket IO.
	reader := &vaultReadyReader{check: func() error { return errors.New("synthetic-private-authority-error") }}
	if n, err := reader.Read(make([]byte, 16)); n != 0 || !errors.Is(err, vault.ErrNativeInput) || reader.ready {
		t.Fatal("revoked peer read/released a frame")
	}
}
