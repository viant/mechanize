package localrpc

import (
	"bytes"
	"context"
	"encoding/hex"
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
	"github.com/viant/mechanize/security/keychain"
	"github.com/viant/mechanize/vault"
	"github.com/viant/scy/kms"
)

// Same independent MVLT v2 golden bytes as vault/record_frame_test.go and the
// Swift codec fixture: arbitrary/key; login=fixture-user; token=00 ff 42.
const socketRecordGolden = "4d564c54000000020000003e0000000d6172626974726172792f6b657900000002000000056c6f67696e0000000c666978747572652d7573657200000005746f6b656e0000000300ff42"
const socketRecordAccount = "account-00112233-4455-6677-8899-aabbccddeeff"

type socketRecordCipher struct {
	*vault.Cipher
	unready atomic.Bool
	mutated atomic.Bool
}

func (c *socketRecordCipher) Ready(ctx context.Context, version string) error {
	if c.unready.Load() {
		return errors.New("synthetic-private-key-error")
	}
	return c.Cipher.Ready(ctx, version)
}
func (c *socketRecordCipher) Encrypt(ctx context.Context, key *kms.Key, plain []byte) ([]byte, error) {
	result, err := c.Cipher.Encrypt(ctx, key, plain)
	if err == nil {
		c.mutated.Store(true)
	}
	return result, err
}

type socketRecordVerifier struct {
	principal auth.Principal
	revoked   atomic.Bool
	calls     atomic.Int32
}

func (v *socketRecordVerifier) Verify(ctx context.Context, raw string) (auth.Principal, error) {
	v.calls.Add(1)
	if v.revoked.Load() {
		return auth.Principal{}, errors.New("synthetic-private-verifier-error")
	}
	return (fixtureVerifier{v.principal}).Verify(ctx, raw)
}

type recordSocketFixture struct {
	options        Options
	store          *vault.RecordStore
	credentials    *vault.Store
	cipher         *socketRecordCipher
	gate           *vault.ExposureGate
	entry          *vault.NativeEntryController
	windows        *socketEntryWindows
	principal      auth.Principal
	human          context.Context
	verifier       *socketRecordVerifier
	entryID        string
	denyEnrollment atomic.Bool
	denyPeer       atomic.Bool
	rejectAck      atomic.Bool
	authorizations atomic.Int32
	handled        atomic.Int32
}

func newRecordSocketFixture(t *testing.T) *recordSocketFixture {
	t.Helper()
	dir, err := os.MkdirTemp("/private/tmp", "mc-record-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f := &recordSocketFixture{gate: &vault.ExposureGate{}}
	f.principal, _ = auth.NewPrincipal("fixture", "", "native-record-owner", []string{"consent:admin"})
	f.principal.ClientID = "signed-console"
	f.human, _ = auth.WithNativeHuman(auth.WithPrincipal(context.Background(), f.principal))
	f.cipher = &socketRecordCipher{Cipher: &vault.Cipher{Keys: socketFixtureKeys{}}}
	f.store, err = vault.NewRecordStore(filepath.Join(dir, "records"), "fixture-v1", f.cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	legacy, err := vault.NewStore(filepath.Join(dir, "credentials"), "fixture-v1", &vault.Cipher{Keys: socketFixtureKeys{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { legacy.Close() })
	f.credentials = legacy
	input, err := vault.NewNativeInputService(legacy, f.gate)
	if err != nil {
		t.Fatal(err)
	}
	records, err := vault.NewNativeRecordInputService(f.store, f.gate)
	if err != nil {
		t.Fatal(err)
	}
	f.windows = &socketEntryWindows{gate: f.gate}
	f.entry, err = vault.NewNativeEntryController(f.gate, f.windows)
	if err != nil {
		t.Fatal(err)
	}
	f.verifier = &socketRecordVerifier{principal: f.principal}
	f.options = Options{SocketPath: filepath.Join(dir, "ui.sock"), Verifier: f.verifier, VaultInput: input, VaultRecords: records, VaultEntry: f.entry,
		VerifyPeer: func(*net.UnixConn) error {
			if f.denyPeer.Load() {
				return errors.New("synthetic-private-peer-error")
			}
			return nil
		},
		AuthorizeVault: func(ctx context.Context, p auth.Principal) error {
			f.authorizations.Add(1)
			if !auth.NativeHuman(ctx) || p.Namespace != f.principal.Namespace || p.ClientID != f.principal.ClientID || f.denyEnrollment.Load() || (f.rejectAck.Load() && f.cipher.mutated.Load()) {
				return errors.New("synthetic-private-enrollment-error")
			}
			return nil
		},
		Handle: func(context.Context, string, json.RawMessage) (any, error) {
			f.handled.Add(1)
			return nil, errors.New("record request reached generic handler")
		},
	}
	return f
}
func (f *recordSocketFixture) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server, err := New(ctx, f.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
}
func (f *recordSocketFixture) protect(t *testing.T, confirm bool) {
	t.Helper()
	var err error
	f.entryID, err = f.entry.Begin(f.human, vault.Target{Origin: vault.NativeRecordEntryOrigin, Account: socketRecordAccount})
	if err != nil {
		t.Fatal(err)
	}
	if confirm {
		if err = f.entry.Confirm(f.human, f.entryID); err != nil {
			t.Fatal(err)
		}
	}
}
func (f *recordSocketFixture) connect(t *testing.T) (*net.UnixConn, string) {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: f.options.SocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err = c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	hello := send(t, c, map[string]any{"jsonrpc": "2.0", "id": "hello", "method": "hello", "params": map[string]any{"protocolVersion": 1, "credential": "fixture-enrollment", "clientBundleID": "com.viant.mechanize.consent"}})
	if hello.Error != nil {
		t.Fatal("fixture hello rejected")
	}
	return c, hello.Result.(map[string]any)["sessionID"].(string)
}
func (f *recordSocketFixture) params(session string) map[string]any {
	return map[string]any{"sessionID": session, "entryID": f.entryID, "accountAlias": socketRecordAccount}
}
func sendRecordHeader(t *testing.T, c *net.UnixConn, method string, params any) response {
	t.Helper()
	return send(t, c, map[string]any{"jsonrpc": "2.0", "id": "transaction", "method": method, "params": params})
}
func sendRecordBody(t *testing.T, c *net.UnixConn, raw []byte) response {
	t.Helper()
	if _, err := c.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	result := vaultSocketRead(t, c)
	serialized, _ := json.Marshal(result)
	for _, private := range []string{"arbitrary/key", "fixture-user", "login", "token", "synthetic-private"} {
		if bytes.Contains(serialized, []byte(private)) {
			t.Fatal("private response disclosure")
		}
	}
	var extra [1]byte
	if n, err := c.Read(extra[:]); n != 0 || err != io.EOF {
		t.Fatal("record transaction connection remained reusable", err)
	}
	return result
}
func recordSocketGolden(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(socketRecordGolden)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func responseRecordMetadata(t *testing.T, r response) vault.RecordMetadata {
	t.Helper()
	if r.Error != nil {
		t.Fatal("record operation failed", r.Error.Code)
	}
	b, err := json.Marshal(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	var meta vault.RecordMetadata
	if json.Unmarshal(b, &meta) != nil || !canonicalRecordHex(meta.Reference.ID, 32) || !canonicalRecordHex(meta.Revision, 32) {
		t.Fatal("invalid opaque result")
	}
	return meta
}
func requireRecordReady(t *testing.T, r response) {
	t.Helper()
	result, ok := r.Result.(map[string]any)
	if r.Error != nil || !ok || result["nativeInputReady"] != true || len(result) != 1 {
		t.Fatal("binary admission missing")
	}
}
func TestVaultRecordSocketGoldenCRUDAndDedicatedRouting(t *testing.T) {
	f := newRecordSocketFixture(t)
	f.start(t)
	f.protect(t, true)
	c, session := f.connect(t)
	requireRecordReady(t, sendRecordHeader(t, c, "vault.record.create", f.params(session)))
	created := responseRecordMetadata(t, sendRecordBody(t, c, recordSocketGolden(t)))
	stored, err := f.store.Lookup(f.human, []byte("arbitrary/key"))
	if err != nil || stored != created {
		t.Fatal("golden encrypted record not independently found", err)
	}
	c, session = f.connect(t)
	params := f.params(session)
	params["refID"] = created.Reference.ID
	params["revision"] = created.Revision
	requireRecordReady(t, sendRecordHeader(t, c, "vault.record.update", params))
	updated := responseRecordMetadata(t, sendRecordBody(t, c, recordSocketGolden(t)))
	if updated.Reference != created.Reference || updated.Revision == created.Revision {
		t.Fatal("revision update failed")
	}
	c, session = f.connect(t)
	params = f.params(session)
	params["refID"] = updated.Reference.ID
	params["revision"] = updated.Revision
	deleted := sendRecordHeader(t, c, "vault.record.delete", params)
	result, ok := deleted.Result.(map[string]any)
	if deleted.Error != nil || !ok || len(result) != 1 || result["deleted"] != true {
		t.Fatal("delete result")
	}
	var extra [1]byte
	if n, err := c.Read(extra[:]); n != 0 || err != io.EOF {
		t.Fatal("delete reused connection", err)
	}
	if _, err = f.store.Metadata(f.human, updated.Reference); !errors.Is(err, vault.ErrMissing) {
		t.Fatal("delete not persisted", err)
	}
	if f.handled.Load() != 0 || f.verifier.calls.Load() < 14 || f.authorizations.Load() < 12 {
		t.Fatal("dedicated routing or repeated authority checks missing")
	}
}
func TestVaultRecordSocketRefusesBeforeRequestingBinaryBytes(t *testing.T) {
	for _, mode := range []string{"unregistered", "unready", "unprotected", "unconfirmed", "wrong-entry", "bad-entry", "wrong-account", "bad-ref", "bad-revision", "create-ref", "create-revision", "missing-ref", "stale-revision", "origin-field", "secret-field", "enrollment"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecordSocketFixture(t)
			if mode == "unregistered" {
				f.options.VaultRecords = nil
			}
			f.start(t)
			if mode != "unprotected" {
				f.protect(t, mode != "unconfirmed")
			} else {
				f.entryID = strings.Repeat("a", 64)
			}
			c, session := f.connect(t)
			params := f.params(session)
			method := "vault.record.create"
			switch mode {
			case "unready":
				f.cipher.unready.Store(true)
			case "wrong-entry":
				params["entryID"] = strings.Repeat("b", 64)
			case "bad-entry":
				params["entryID"] = "invalid"
			case "wrong-account":
				params["accountAlias"] = strings.Repeat("b", 64)
			case "bad-ref":
				method = "vault.record.update"
				params["refID"] = "invalid"
				params["revision"] = strings.Repeat("a", 64)
			case "bad-revision":
				method = "vault.record.update"
				params["refID"] = strings.Repeat("a", 64)
				params["revision"] = "invalid"
			case "create-ref":
				params["refID"] = ""
			case "create-revision":
				params["revision"] = ""
			case "missing-ref":
				method = "vault.record.update"
				params["refID"] = strings.Repeat("a", 64)
				params["revision"] = strings.Repeat("b", 64)
			case "stale-revision":
				v, err := vault.NewRecordValues([]byte("existing"), [][2][]byte{{[]byte("field"), []byte("value")}})
				if err != nil {
					t.Fatal(err)
				}
				meta, err := f.store.Create(f.human, v)
				if err != nil {
					t.Fatal(err)
				}
				f.cipher.mutated.Store(false)
				method = "vault.record.update"
				params["refID"] = meta.Reference.ID
				params["revision"] = strings.Repeat("a", 64)
			case "origin-field":
				params["origin"] = "https://example.test"
			case "secret-field":
				params["value"] = "synthetic-private-input"
			case "enrollment":
				f.denyEnrollment.Store(true)
			}
			r := sendRecordHeader(t, c, method, params)
			if r.Error == nil || r.Error.Code != -32020 || r.Result != nil || f.cipher.mutated.Load() || f.handled.Load() != 0 {
				t.Fatal("unsafe channel requested bytes or mutated")
			}
			var b [1]byte
			if n, err := c.Read(b[:]); n != 0 || err != io.EOF {
				t.Fatal("rejected connection reusable", err)
			}
		})
	}
}
func TestVaultRecordSocketRechecksPeerSessionAndEnrollmentBeforeEveryRead(t *testing.T) {
	for _, mode := range []string{"peer", "credential", "enrollment"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecordSocketFixture(t)
			f.start(t)
			f.protect(t, true)
			c, session := f.connect(t)
			requireRecordReady(t, sendRecordHeader(t, c, "vault.record.create", f.params(session)))
			switch mode {
			case "peer":
				f.denyPeer.Store(true)
			case "credential":
				f.verifier.revoked.Store(true)
			case "enrollment":
				f.denyEnrollment.Store(true)
			}
			// The header read was admitted before readiness. Revocation must stop
			// the next read, so no payload containing record secrets is sent.
			r := sendRecordBody(t, c, recordSocketGolden(t)[:12])
			if r.Error == nil || r.Error.Code != -32020 || f.cipher.mutated.Load() || f.handled.Load() != 0 {
				t.Fatal("revoked actor admitted secret payload")
			}
		})
	}
}
func TestVaultRecordSocketLostAcknowledgementIsSanitizedAndSingleUse(t *testing.T) {
	f := newRecordSocketFixture(t)
	f.rejectAck.Store(true)
	f.start(t)
	f.protect(t, true)
	c, session := f.connect(t)
	requireRecordReady(t, sendRecordHeader(t, c, "vault.record.create", f.params(session)))
	r := sendRecordBody(t, c, recordSocketGolden(t))
	if r.Error == nil || r.Error.Code != -32021 || r.Result != nil {
		t.Fatal("post-write acknowledgement refusal lost uncertainty")
	}
	rows, err := f.store.Inventory(f.human)
	if err != nil || len(rows) != 1 || f.handled.Load() != 0 {
		t.Fatal("committed record not inspectable", err)
	}
}
func TestVaultRecordRegistrationRequiresPolicyAndExactSharedGate(t *testing.T) {
	for _, mode := range []string{"nil-enrollment", "nil-peer", "nil-verifier", "no-lifecycle", "other-gate", "fixture-provider", "unguarded-key-setup"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecordSocketFixture(t)
			switch mode {
			case "nil-enrollment":
				f.options.AuthorizeVault = nil
			case "nil-peer":
				f.options.VerifyPeer = nil
			case "nil-verifier":
				f.options.Verifier = nil
			case "no-lifecycle":
				f.options.VaultEntry = nil
			case "other-gate":
				f.options.VaultRecords, _ = vault.NewNativeRecordInputService(f.store, &vault.ExposureGate{})
			case "unguarded-key-setup":
				// No provisioning method is called: this inert fixture proves the
				// registration check rejects a legacy-only guard before socket creation.
				var err error
				f.options.VaultKeySetup, err = vault.NewNativeKeySetup(f.credentials, &keychain.MasterKeyProvisioner{})
				if err != nil {
					t.Fatal(err)
				}
			case "fixture-provider":
				f.options.VaultRecords, _ = vault.NewNativeRecordInputService(f.store, &socketFixtureProtection{})
			}
			if server, err := New(context.Background(), f.options); err == nil {
				server.Close()
				t.Fatal("unsafe registration accepted")
			}
		})
	}
}
func TestVaultRecordMetadataSchemaIsClosedCanonicalAndSecretFree(t *testing.T) {
	base := `{"sessionID":"` + strings.Repeat("a", 48) + `","entryID":"` + strings.Repeat("b", 64) + `","accountAlias":"` + socketRecordAccount + `"}`
	for _, raw := range []string{
		strings.TrimSuffix(base, "}") + `,"sessionID":"` + strings.Repeat("a", 48) + `"}`,
		strings.TrimSuffix(base, "}") + `,"key":"synthetic"}`,
		strings.TrimSuffix(base, "}") + `,"fieldNames":[]}`,
		strings.TrimSuffix(base, "}") + `,"origin":"https://example.test"}`,
		strings.TrimSuffix(base, "}") + `,"refID":null}`,
		strings.TrimSuffix(base, "}") + `,"revision":""}`,
		strings.Replace(base, strings.Repeat("a", 48), strings.Repeat("A", 48), 1),
		strings.Replace(base, `"accountAlias":"`+socketRecordAccount+`"`, `"accountAlias":null`, 1),
		base + ` {}`,
	} {
		if _, err := decodeVaultRecordRequest([]byte(raw), "vault.record.create"); err == nil {
			t.Fatal("noncanonical/unknown metadata accepted")
		}
	}
	if _, err := decodeVaultRecordRequest([]byte(base), "vault.record.create"); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeVaultRecordRequest([]byte(base), "vault.record.update"); err == nil {
		t.Fatal("update without reference accepted")
	}
	// Malformed v1 content is never interpreted as JSON or handled generically.
	f := newRecordSocketFixture(t)
	f.start(t)
	f.protect(t, true)
	c, session := f.connect(t)
	requireRecordReady(t, sendRecordHeader(t, c, "vault.record.create", f.params(session)))
	legacy := []byte{'M', 'V', 'L', 'T', 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 'a', 'b'}
	r := sendRecordBody(t, c, legacy)
	if r.Error == nil || r.Error.Code != -32020 || f.handled.Load() != 0 {
		t.Fatal("v1 record payload accepted")
	}
}

func TestVaultRecordSocketEntryOwnershipAndRetirementBeforeBinaryAdmission(t *testing.T) {
	for _, mode := range []string{"namespace", "client", "retired"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecordSocketFixture(t)
			if mode == "namespace" {
				p, err := auth.NewPrincipal("fixture", "", "other-record-owner", []string{"consent:admin"})
				if err != nil {
					t.Fatal(err)
				}
				p.ClientID = f.principal.ClientID
				f.verifier.principal = p
			}
			if mode == "client" {
				p := f.principal
				p.ClientID = "other-signed-console"
				f.verifier.principal = p
			}
			// Admit both enrolled fixture identities at host policy so this test
			// specifically reaches the independent lifecycle ownership boundary.
			f.options.AuthorizeVault = func(ctx context.Context, p auth.Principal) error {
				if !auth.NativeHuman(ctx) || !p.HasScope("consent:admin") {
					return auth.ErrUnauthorized
				}
				return nil
			}
			f.start(t)
			f.protect(t, true)
			if mode == "retired" {
				if err := f.entry.Retire(f.human, f.entryID); err != nil {
					t.Fatal(err)
				}
			}
			c, session := f.connect(t)
			r := sendRecordHeader(t, c, "vault.record.create", f.params(session))
			if r.Error == nil || r.Error.Code != -32020 || r.Result != nil || f.cipher.mutated.Load() || f.handled.Load() != 0 {
				t.Fatal("unowned/retired lifecycle admitted bytes")
			}
		})
	}
}
