package localrpc

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/vault"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func nativeImportSocketFixture(t *testing.T) (*recordSocketFixture, vault.EntryMetadata) {
	t.Helper()
	f := newRecordSocketFixture(t)
	f.store.Close()
	f.credentials.Close()
	dir := filepath.Dir(f.options.SocketPath)
	cipher := &vault.Cipher{Keys: socketFixtureKeys{}}
	var e error
	f.store, e = vault.NewRecordStore(filepath.Join(dir, "records"), "fixture-v1", cipher)
	if e != nil {
		t.Fatal(e)
	}
	f.credentials, e = vault.NewStore(filepath.Join(dir, "credentials"), "fixture-v1", cipher)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.store.Close(); f.credentials.Close() })
	f.options.VaultInput, _ = vault.NewNativeInputService(f.credentials, f.gate)
	f.options.VaultRecords, _ = vault.NewNativeRecordInputService(f.store, f.gate)
	target := vault.Target{Origin: vault.NativeRecordEntryOrigin, Account: socketRecordAccount}
	if _, e = f.credentials.Create(f.human, target, []byte("import-user-canary"), []byte("import-password-canary")); e != nil {
		t.Fatal(e)
	}
	metadata, e := f.credentials.Metadata(f.human, target)
	if e != nil {
		t.Fatal(e)
	}
	f.protect(t, true)
	return f, metadata
}
func importParams(f *recordSocketFixture, meta vault.EntryMetadata, session string) map[string]any {
	return map[string]any{"sessionID": session, "entryID": f.entryID, "origin": vault.NativeRecordEntryOrigin, "accountAlias": socketRecordAccount, "resourceURL": meta.Reference.ResourceURL, "revision": meta.Revision}
}
func TestNativeImportSocketNeverSendsValuesOrUsesGenericHandler(t *testing.T) {
	f, meta := nativeImportSocketFixture(t)
	f.start(t)
	var first vault.RecordMetadata
	for _, method := range []string{"vault.record.importCredential", "vault.record.inspectImport", "vault.record.importCredential"} {
		c, session := f.connect(t)
		reply := send(t, c, map[string]any{"jsonrpc": "2.0", "id": "import", "method": method, "params": importParams(f, meta, session)})
		result := responseRecordMetadata(t, reply)
		if first.Reference.ID == "" {
			first = result
		} else if result != first {
			t.Fatal("import duplicated destination")
		}
		raw, _ := json.Marshal(reply)
		for _, secret := range []string{"import-user-canary", "import-password-canary", meta.Reference.ResourceURL} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("private import output leaked")
			}
		}
		var tail [1]byte
		if n, e := c.Read(tail[:]); n != 0 || e != io.EOF {
			t.Fatal("import connection reusable", e)
		}
		c.Close()
	}
	if f.handled.Load() != 0 {
		t.Fatal("import reached generic handler")
	}
	rows, e := f.store.Inventory(f.human)
	if e != nil || len(rows) != 1 {
		t.Fatal("duplicate records", e)
	}
}
func TestNativeImportLostAcknowledgementIsReadOnlyReconcilable(t *testing.T) {
	f, meta := nativeImportSocketFixture(t)
	s := &Server{options: f.options}
	raw, _ := json.Marshal(importParams(f, meta, strings.Repeat("a", 48)))
	r := request{JSONRPC: "2.0", ID: "import", Method: "vault.record.importCredential", Params: raw}
	checks := 0
	reply := s.vaultImport(f.human, r, func() error {
		checks++
		if checks == 2 {
			return errors.New("peer changed after write")
		}
		return nil
	})
	if reply.Error == nil || reply.Error.Code != -32021 || reply.Result != nil {
		t.Fatal("uncertain acknowledgement not retained")
	}
	r.Method = "vault.record.inspectImport"
	reply = s.vaultImport(f.human, r, func() error { return nil })
	first := responseRecordMetadata(t, reply)
	reply = s.vaultImport(f.human, r, func() error { return nil })
	if responseRecordMetadata(t, reply) != first {
		t.Fatal("reconciliation changed destination")
	}
}
func TestNativeImportClosedMetadataAndNativeAuthority(t *testing.T) {
	f, meta := nativeImportSocketFixture(t)
	params := importParams(f, meta, strings.Repeat("a", 48))
	s := &Server{options: f.options}
	for _, field := range []string{"username", "password", "sourcePath", "nativeHuman", "protected"} {
		copy := map[string]any{}
		for k, v := range params {
			copy[k] = v
		}
		copy[field] = "canary"
		raw, _ := json.Marshal(copy)
		if _, e := decodeVaultImport(raw); e == nil {
			t.Fatal("open import metadata", field)
		}
	}
	raw, _ := json.Marshal(params)
	reply := s.vaultImport(context.Background(), request{JSONRPC: "2.0", ID: "x", Method: "vault.record.importCredential", Params: raw}, func() error { return nil })
	if reply.Error == nil {
		t.Fatal("unauthenticated import")
	}
	reply = s.vaultImport(f.human, request{JSONRPC: "2.0", ID: "x", Method: "vault.record.importCredential", Params: raw}, func() error { return errors.New("unverified peer") })
	if reply.Error == nil {
		t.Fatal("unverified peer import")
	}
	entries, e := f.store.Inventory(f.human)
	if e != nil || len(entries) != 0 {
		t.Fatal("refused import wrote credentials", e)
	}
}
