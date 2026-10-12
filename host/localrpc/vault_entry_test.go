package localrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/vault"
)

type socketEntryWindows struct {
	gate     *vault.ExposureGate
	closed   atomic.Bool
	prepared atomic.Int32
}

func (w *socketEntryWindows) Prepare(context.Context, string, vault.Target) error {
	w.prepared.Add(1)
	if release, err := w.gate.AcquireExposure(); err == nil {
		release()
		return errors.New("entry was not protected before preparation")
	}
	return nil
}
func (w *socketEntryWindows) VerifyClosed(context.Context, string) error {
	if !w.closed.Load() {
		return errors.New("synthetic-window-cleanup-canary")
	}
	return nil
}
func (w *socketEntryWindows) VerifyOpen(context.Context, string) error { return nil }

func TestNativeVaultLifecycleSocketDisconnectRetainsProtection(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "mc-entry-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	os.Chmod(dir, 0700)
	p, _ := auth.NewPrincipal("fixture", "", "entry-owner", []string{"consent:admin"})
	p.ClientID = "signed-console"
	human, _ := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
	store, err := vault.NewStore(filepath.Join(dir, "vault"), "fixture-v1", &vault.Cipher{Keys: socketFixtureKeys{}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	gate := &vault.ExposureGate{}
	windows := &socketEntryWindows{gate: gate}
	entry, _ := vault.NewNativeEntryController(gate, windows)
	input, _ := vault.NewNativeInputService(store, gate)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := New(ctx, Options{SocketPath: filepath.Join(dir, "ui.sock"), Verifier: fixtureVerifier{p}, VerifyPeer: func(*net.UnixConn) error { return nil }, VaultInput: input, VaultEntry: entry, AuthorizeVault: func(_ context.Context, actor auth.Principal) error {
		if actor.Namespace != p.Namespace {
			return auth.ErrUnauthorized
		}
		return nil
	}, Handle: func(context.Context, string, json.RawMessage) (any, error) {
		t.Error("lifecycle reached generic handler")
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	connect := func() (*net.UnixConn, string) {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(dir, "ui.sock"), Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(5 * time.Second))
		r := send(t, c, map[string]any{"jsonrpc": "2.0", "id": "hello", "method": "hello", "params": map[string]any{"protocolVersion": 1, "credential": "fixture-enrollment", "clientBundleID": "com.viant.mechanize.consent"}})
		return c, r.Result.(map[string]any)["sessionID"].(string)
	}
	c, session := connect()
	begin := func(id string, extra map[string]any) response {
		params := map[string]any{"sessionID": session, "origin": "https://example.test", "accountAlias": "fixture-account"}
		for k, v := range extra {
			params[k] = v
		}
		return send(t, c, map[string]any{"jsonrpc": "2.0", "id": id, "method": "vault.entry.begin", "params": params})
	}
	if r := begin("invalid-begin", map[string]any{"cleanupConfirmed": true}); r.Error == nil || windows.prepared.Load() != 0 {
		t.Fatal("client cleanup assertion accepted")
	}
	r := begin("begin", nil)
	if r.Error != nil {
		t.Fatal("begin rejected")
	}
	id, ok := r.Result.(map[string]any)["entryID"].(string)
	if !ok || len(id) != 64 {
		t.Fatal("entry ID missing")
	}
	if release, err := gate.AcquireExposure(); err == nil {
		release()
		t.Fatal("entry exposed")
	}
	for _, extra := range []map[string]any{nil, {"entryID": "wrong-entry"}} {
		secretConnection, secretSession := connect()
		if rejected := vaultSocketSend(t, secretConnection, secretSession, extra); rejected.Error == nil {
			t.Fatal("unbound input requested credential bytes")
		}
	}
	unconfirmedConnection, unconfirmedSession := connect()
	if refused := vaultSocketSend(t, unconfirmedConnection, unconfirmedSession, map[string]any{"entryID": id}); refused.Error == nil {
		t.Fatal("unconfirmed window accepted credential bytes")
	}
	confirmed := send(t, c, map[string]any{"jsonrpc": "2.0", "id": "confirm", "method": "vault.entry.confirm", "params": map[string]any{"sessionID": session, "entryID": id}})
	if confirmed.Error != nil || confirmed.Result.(map[string]any)["entryProtected"] != true {
		t.Fatal("window confirmation failed")
	}
	secretConnection, secretSession := connect()
	created := vaultSocketSend(t, secretConnection, secretSession, map[string]any{"entryID": id})
	if created.Error != nil {
		t.Fatal("protected dedicated input rejected")
	}
	if err = gate.WithEntry(human, vault.Target{Origin: "https://example.test", Account: "fixture-account"}, func() error { return nil }); err != nil {
		t.Fatal("secret transaction retired the separate lifecycle connection")
	}
	closeRequest := func(conn *net.UnixConn, s, requestID string) response {
		return send(t, conn, map[string]any{"jsonrpc": "2.0", "id": requestID, "method": "vault.entry.close", "params": map[string]any{"sessionID": s, "entryID": id}})
	}
	if r = closeRequest(c, session, "close-before-cleanup"); r.Error == nil {
		t.Fatal("unverified cleanup released block")
	}
	if raw, _ := json.Marshal(r); bytes.Contains(raw, []byte("canary")) {
		t.Fatal("private provider error escaped")
	}
	c.Close()
	// The block survives a lifecycle connection disappearing, including loss of
	// the Begin acknowledgement. Reconnection cannot override the native verifier.
	if release, err := gate.AcquireExposure(); err == nil {
		release()
		t.Fatal("disconnect released block")
	}
	c2, s2 := connect()
	r = send(t, c2, map[string]any{"jsonrpc": "2.0", "id": "recover-denied", "method": "vault.entry.recover", "params": map[string]any{"sessionID": s2}})
	if r.Error == nil {
		t.Fatal("reconnect bypassed cleanup")
	}
	windows.closed.Store(true)
	r = send(t, c2, map[string]any{"jsonrpc": "2.0", "id": "recover", "method": "vault.entry.recover", "params": map[string]any{"sessionID": s2}})
	if r.Error != nil || r.Result.(map[string]any)["entryClosed"] != true {
		t.Fatal("verified recovery failed")
	}
	release, err := gate.AcquireExposure()
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err = gate.WithEntry(human, vault.Target{Origin: "https://example.test", Account: "fixture-account"}, func() error { t.Fatal("closed entry accepted bytes"); return nil }); err == nil {
		t.Fatal("closed entry accepted")
	}
}

func TestNativeVaultLifecycleRejectsDifferentExposureGate(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "mc-entry-gate-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	store, err := vault.NewStore(dir, "fixture-v1", &vault.Cipher{Keys: socketFixtureKeys{}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	input, _ := vault.NewNativeInputService(store, &vault.ExposureGate{})
	entry, _ := vault.NewNativeEntryController(&vault.ExposureGate{}, &socketEntryWindows{})
	if _, err = New(context.Background(), Options{VaultInput: input, VaultEntry: entry}); err == nil {
		t.Fatal("different gate accepted")
	}
}
