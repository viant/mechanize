package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func importFixture(t *testing.T) (*NativeRecordInputService, *NativeInputService, context.Context, Target, EntryMetadata) {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	cipher := &Cipher{Keys: fixtureKeys{}}
	source, e := NewStore(filepath.Join(dir, "legacy"), "fixture-v1", cipher)
	if e != nil {
		t.Fatal(e)
	}
	records, e := NewRecordStore(filepath.Join(dir, "records"), "fixture-v1", cipher)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { source.Close(); records.Close() })
	p, _ := auth.NewPrincipal("fixture", "", "import-owner", []string{"consent:admin"})
	p.ClientID = "native-console"
	ctx, _ := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
	target := Target{Origin: "https://fixture.invalid", Account: "opaque"}
	if _, e = source.Create(ctx, target, []byte("username-import-canary"), []byte("password-import-canary")); e != nil {
		t.Fatal(e)
	}
	metadata, e := source.Metadata(ctx, target)
	if e != nil {
		t.Fatal(e)
	}
	gate := &ExposureGate{}
	lease, e := gate.Begin(ctx, target, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { lease.Close(ctx) })
	from, _ := NewNativeInputService(source, gate)
	to, _ := NewNativeRecordInputService(records, gate)
	return to, from, ctx, target, metadata
}
func TestNativeImportPreservesSourceAndReconcilesWithoutDuplicateCopy(t *testing.T) {
	to, from, ctx, target, source := importFixture(t)
	dest, e := to.ImportCredential(ctx, from, target, source.Reference, source.Revision, false)
	if e != nil {
		t.Fatal(e)
	}
	actual, e := from.store.Metadata(ctx, target)
	if e != nil || actual != source {
		t.Fatal("legacy source changed", e)
	}
	for _, inspect := range []bool{true, false, true} {
		again, e := to.ImportCredential(ctx, from, target, source.Reference, source.Revision, inspect)
		if e != nil || again != dest {
			t.Fatal("reconciliation did not return exact destination", e)
		}
	}
	entries, e := to.store.Inventory(ctx)
	if e != nil || len(entries) != 1 {
		t.Fatal("duplicate records", e)
	}
	raw, _ := json.Marshal(dest)
	if strings.Contains(string(raw), "canary") || strings.Contains(string(raw), target.Origin) {
		t.Fatal("import receipt leaked values/routing")
	}
	p, _ := auth.FromContext(ctx)
	meta, plain, e := to.store.load(ctx, p.Namespace, dest.Reference.ID)
	defer clear(plain)
	if e != nil || meta != dest {
		t.Fatal(e)
	}
	values, e := recordCredentials(plain)
	if e != nil || !bytes.Equal(values.username, []byte("username-import-canary")) || !bytes.Equal(values.password, []byte("password-import-canary")) {
		t.Fatal("wrong copied credentials")
	}
	// Durable receipt survives reopening, not just an in-memory request cache.
	root, version, cipher := to.store.store.path, to.store.store.version, to.store.store.cipher
	to.store.Close()
	reopened, e := NewRecordStore(root, version, cipher)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	to.store = reopened
	if result, e := to.ImportCredential(ctx, from, target, source.Reference, source.Revision, true); e != nil || result != dest {
		t.Fatal("restart lost receipt", e)
	}
}
func TestNativeImportPreparedOrDeletedDestinationNeverReplays(t *testing.T) {
	for _, mode := range []string{"prepared-no-copy", "prepared-with-copy", "deleted", "changed", "tampered"} {
		t.Run(mode, func(t *testing.T) {
			to, from, ctx, target, source := importFixture(t)
			p, _ := auth.FromContext(ctx)
			hash := importIdentity(p.Namespace, source.Reference, source.Revision)
			var dest RecordMetadata
			if mode == "prepared-no-copy" {
				e := to.store.store.writeLock(ctx, func() error {
					return to.store.writeImport(ctx, importReceipt{Version: to.store.store.version, Namespace: p.Namespace, Source: hash, Destination: strings.Repeat("d", 64)}, true)
				})
				if e != nil {
					t.Fatal(e)
				}
			} else {
				var e error
				dest, e = to.ImportCredential(ctx, from, target, source.Reference, source.Revision, false)
				if e != nil {
					t.Fatal(e)
				}
				switch mode {
				case "prepared-with-copy":
					e = to.store.store.writeLock(ctx, func() error {
						r, e := to.store.readImport(ctx, p.Namespace, hash)
						if e != nil {
							return e
						}
						r.Revision = ""
						return to.store.writeImport(ctx, r, false)
					})
				case "deleted":
					e = to.store.Delete(ctx, dest.Reference, dest.Revision)
				case "changed":
					v, _ := NewRecordValues([]byte("changed-key"), [][2][]byte{{[]byte("username"), []byte("changed")}, {[]byte("password"), []byte("changed")}})
					_, e = to.store.Update(ctx, dest.Reference, dest.Revision, v)
				case "tampered":
					e = os.WriteFile(filepath.Join(to.store.store.path, importPrefix+hash), []byte(`{"receipt":"tampered"}`), 0600)
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			before, e := to.store.importCount()
			if e != nil {
				t.Fatal(e)
			}
			for _, inspect := range []bool{true, false} {
				result, e := to.ImportCredential(ctx, from, target, source.Reference, source.Revision, inspect)
				if mode == "prepared-with-copy" {
					if e != nil || result != dest {
						t.Fatal("lost ack could not reconcile", e)
					}
				} else if e == nil {
					t.Fatal("uncertain/deleted/changed import replayed")
				}
			}
			after, _ := to.store.importCount()
			if before != after {
				t.Fatal("reconciliation wrote new receipt")
			}
			if mode == "prepared-no-copy" || mode == "deleted" {
				entries, e := to.store.Inventory(ctx)
				if e != nil || len(entries) != 0 {
					t.Fatal("missing copy replayed", e)
				}
			}
		})
	}
}
func TestNativeImportRejectsUnauthorizedStaleOrDifferentCustody(t *testing.T) {
	to, from, ctx, target, source := importFixture(t)
	if _, e := to.ImportCredential(fixtureContext("import-owner", false), from, target, source.Reference, source.Revision, false); !errors.Is(e, auth.ErrUnauthorized) {
		t.Fatal("non-native import accepted", e)
	}
	if _, e := to.ImportCredential(ctx, from, target, source.Reference, strings.Repeat("f", 64), false); e == nil {
		t.Fatal("stale source copied")
	}
	other := *from
	other.protection = &ExposureGate{}
	if _, e := to.ImportCredential(ctx, &other, target, source.Reference, source.Revision, false); e == nil {
		t.Fatal("different protection gate admitted")
	}
	if _, e := to.ImportCredential(ctx, from, target, Reference{ResourceURL: "file:///untrusted"}, source.Revision, false); e == nil {
		t.Fatal("arbitrary source path admitted")
	}
	if n, e := to.store.importCount(); e != nil || n != 0 {
		t.Fatal("rejected request reserved import", e)
	}
}
