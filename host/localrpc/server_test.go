package localrpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

type fixtureVerifier struct{ principal auth.Principal }

func (v fixtureVerifier) Verify(_ context.Context, raw string) (auth.Principal, error) {
	if raw != "fixture-enrollment" {
		return auth.Principal{}, errors.New("invalid")
	}
	return v.principal, nil
}
func send(t *testing.T, c net.Conn, value any) response {
	t.Helper()
	raw, _ := json.Marshal(value)
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(raw)))
	if _, e := c.Write(append(h[:], raw...)); e != nil {
		t.Fatal(e)
	}
	if _, e := io.ReadFull(c, h[:]); e != nil {
		t.Fatal(e)
	}
	n := binary.BigEndian.Uint32(h[:])
	if n > MaxFrameBytes {
		t.Fatal("oversized response")
	}
	body := make([]byte, n)
	if _, e := io.ReadFull(c, body); e != nil {
		t.Fatal(e)
	}
	var r response
	if e := json.Unmarshal(body, &r); e != nil {
		t.Fatal(e)
	}
	return r
}
func TestVerifiedConsoleAndSessionBoundary(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "mc-consent-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	_ = os.Chmod(dir, 0700)
	p, _ := auth.NewPrincipal("fixture", "", "human", []string{"consent:admin"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var called atomic.Int32
	s, e := New(ctx, Options{SocketPath: filepath.Join(dir, "consent.sock"), Verifier: fixtureVerifier{p}, VerifyPeer: func(*net.UnixConn) error { return nil }, Handle: func(ctx context.Context, method string, raw json.RawMessage) (any, error) {
		actor, e := auth.FromContext(ctx)
		if e != nil || actor.Namespace != p.Namespace {
			t.Fatal("verified actor missing")
		}
		called.Add(1)
		return map[string]any{"requests": []any{}, "grants": []any{}}, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e := net.Dial("unix", filepath.Join(dir, "consent.sock"))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	hello := send(t, c, map[string]any{"jsonrpc": "2.0", "id": "1", "method": "hello", "params": map[string]any{"protocolVersion": 1, "credential": "fixture-enrollment", "clientBundleID": "com.viant.mechanize.consent"}})
	result := hello.Result.(map[string]any)
	session := result["sessionID"].(string)
	snap := send(t, c, map[string]any{"jsonrpc": "2.0", "id": "2", "method": "snapshot", "params": map[string]any{"sessionID": session}})
	if snap.Error != nil || called.Load() != 1 {
		t.Fatal("snapshot failed")
	}
	denied := send(t, c, map[string]any{"jsonrpc": "2.0", "id": "3", "method": "execute", "params": map[string]any{"sessionID": session}})
	if denied.Error == nil || called.Load() != 1 {
		t.Fatal("UI socket became arbitrary execution channel")
	}
}
func TestMissingSignedPeerPolicyFailsClosed(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "mc-consent-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	_ = os.Chmod(dir, 0700)
	if _, e := New(context.Background(), Options{SocketPath: filepath.Join(dir, "consent.sock"), Verifier: fixtureVerifier{}, Handle: func(context.Context, string, json.RawMessage) (any, error) { return nil, nil }}); e == nil {
		t.Fatal("missing peer policy accepted")
	}
}

func TestConsoleImageRevocationAfterHandshakeBlocksGenericUIRequest(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "mc-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	p, _ := auth.NewPrincipal("fixture", "", "human", []string{"consent:admin"})
	var revoked atomic.Bool
	var called atomic.Int32
	s, err := New(context.Background(), Options{SocketPath: filepath.Join(dir, "ui.sock"), Verifier: fixtureVerifier{p}, VerifyPeer: func(*net.UnixConn) error {
		if revoked.Load() {
			return errors.New("PRIVATE-PEER-CANARY")
		}
		return nil
	}, Handle: func(context.Context, string, json.RawMessage) (any, error) {
		called.Add(1)
		return map[string]bool{"available": true}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := net.Dial("unix", filepath.Join(dir, "ui.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hello := send(t, c, map[string]any{"jsonrpc": "2.0", "id": "1", "method": "hello", "params": map[string]any{"protocolVersion": 1, "credential": "fixture-enrollment", "clientBundleID": "com.viant.mechanize.consent"}})
	session := hello.Result.(map[string]any)["sessionID"].(string)
	revoked.Store(true)
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "2", "method": "browserSetupMetadata", "params": map[string]any{"sessionID": session}})
	if err != nil {
		t.Fatal(err)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if _, err = c.Write(append(header[:], raw...)); err != nil {
		t.Fatal(err)
	}
	if err = c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadFull(c, header[:])
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("revoked console image retained request authority")
	}
	if called.Load() != 0 {
		t.Fatal("revoked peer reached native handler")
	}
}
