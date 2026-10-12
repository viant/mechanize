package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/scy/kms"
	"golang.org/x/sys/unix"
)

func fixtureRecordStore(t *testing.T) *RecordStore {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	r, err := NewRecordStore(root, "fixture-v1", &Cipher{Keys: fixtureKeys{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}
func recordValues(t *testing.T, key string) RecordValues {
	t.Helper()
	v, err := NewRecordValues([]byte(key), [][2][]byte{{[]byte("synthetic-field-canary"), []byte("synthetic-value-canary")}})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestRecordCRUDOpaqueKeysAndNamespace(t *testing.T) {
	r := fixtureRecordStore(t)
	ctx := fixtureContext("one", true)
	other := fixtureContext("other", true)
	key := "arbitrary / key: 🚀 with no website"
	first, err := r.Create(ctx, recordValues(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if !nativeRevision(first.Reference.ID) || !nativeRevision(first.Revision) {
		t.Fatal("invalid opaque metadata")
	}
	b, _ := json.Marshal(first)
	if bytes.Contains(b, []byte("canary")) || bytes.Contains(b, []byte("arbitrary")) {
		t.Fatal("public metadata disclosure")
	}
	for _, name := range []string{recordMarker, ".vault-write.lock", first.Reference.ID + ".record"} {
		raw, e := os.ReadFile(filepath.Join(r.store.path, name))
		if e != nil {
			t.Fatal(e)
		}
		for _, secret := range []string{key, "synthetic-field-canary", "synthetic-value-canary"} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatal("plaintext on disk")
			}
		}
	}
	meta, err := r.Lookup(ctx, []byte(key))
	if err != nil || meta != first {
		t.Fatal("lookup", err)
	}
	if _, err = r.Create(ctx, recordValues(t, key)); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate accepted", err)
	}
	foreign, err := r.Create(other, recordValues(t, key))
	if err != nil || foreign.Reference == first.Reference {
		t.Fatal("namespace isolation", err)
	}
	if _, err = r.Metadata(other, first.Reference); !errors.Is(err, ErrMissing) {
		t.Fatal("foreign metadata", err)
	}
	inventory, err := r.Inventory(other)
	if err != nil || len(inventory) != 1 || inventory[0] != foreign {
		t.Fatal("foreign inventory", err)
	}
	if err = r.Delete(other, first.Reference, first.Revision); !errors.Is(err, ErrMissing) {
		t.Fatal("foreign delete", err)
	}
	if _, err = r.Update(ctx, first.Reference, strings.Repeat("0", 64), recordValues(t, key)); !errors.Is(err, ErrConflict) {
		t.Fatal("stale update", err)
	}
	second, err := r.Update(ctx, first.Reference, first.Revision, recordValues(t, "renamed arbitrary key"))
	if err != nil || second.Reference != first.Reference || second.Revision == first.Revision {
		t.Fatal("update", err)
	}
	if _, err = r.Lookup(ctx, []byte(key)); !errors.Is(err, ErrMissing) {
		t.Fatal("old key retained", err)
	}
	if err = r.Delete(ctx, second.Reference, first.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("stale delete", err)
	}
	if err = r.Delete(ctx, second.Reference, second.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Metadata(ctx, second.Reference); !errors.Is(err, ErrMissing) {
		t.Fatal("delete", err)
	}
}
func TestRecordValuesWipeOneShotAndSerialization(t *testing.T) {
	r := fixtureRecordStore(t)
	for _, authorized := range []bool{true, false} {
		key, name, value := []byte("synthetic-key"), []byte("synthetic-name"), []byte("synthetic-value")
		v, err := NewRecordValues(key, [][2][]byte{{name, value}})
		if err != nil {
			t.Fatal(err)
		}
		copyOfV := v
		if _, err = json.Marshal(v); err == nil {
			t.Fatal("JSON serialized")
		}
		if _, err = v.MarshalText(); err == nil {
			t.Fatal("text serialized")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(format, v), "synthetic") {
				t.Fatal("format disclosure")
			}
		}
		_, err = r.Create(fixtureContext("one", authorized), v)
		if authorized && err != nil {
			t.Fatal(err)
		}
		if !authorized && !errors.Is(err, auth.ErrUnauthorized) {
			t.Fatal(err)
		}
		for _, b := range [][]byte{key, name, value} {
			if !bytes.Equal(b, make([]byte, len(b))) {
				t.Fatal("input not wiped")
			}
		}
		if _, err = copyOfV.take(); !errors.Is(err, ErrRecord) {
			t.Fatal("copy replay accepted", err)
		}
	}
	invalid := []byte("too-many-identical-fields")
	if _, err := NewRecordValues(invalid, [][2][]byte{{[]byte("a"), []byte("b")}, {[]byte("a"), []byte("c")}}); !errors.Is(err, ErrRecord) || !bytes.Equal(invalid, make([]byte, len(invalid))) {
		t.Fatal("invalid input retained", err)
	}
	v := recordValues(t, "one shot race")
	var wg sync.WaitGroup
	successes := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); b, e := v.take(); successes <- e == nil; clear(b) }()
	}
	wg.Wait()
	close(successes)
	count := 0
	for ok := range successes {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatal("one-shot race")
	}
}
func TestRecordAuthorizationAndCancellation(t *testing.T) {
	r := fixtureRecordStore(t)
	human := fixtureContext("one", true)
	agent := fixtureContext("one", false)
	meta, err := r.Create(human, recordValues(t, "key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Inventory(agent); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	if _, err = r.Metadata(agent, meta.Reference); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	key := []byte("key")
	if _, err = r.Lookup(agent, key); !errors.Is(err, auth.ErrUnauthorized) || !bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("lookup auth/wipe", err)
	}
	if _, err = r.Update(agent, meta.Reference, meta.Revision, recordValues(t, "key")); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	if err = r.Delete(agent, meta.Reference, meta.Revision); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(human)
	cancel()
	v := recordValues(t, "cancel")
	if _, err = r.Create(ctx, v); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = v.take(); !errors.Is(err, ErrRecord) {
		t.Fatal("canceled input reusable")
	}
}
func TestRecordTamperAndAuthenticatedHeaders(t *testing.T) {
	for _, which := range []string{"kind", "version", "namespace", "ciphertext", "tag", "id", "foreign-namespace"} {
		t.Run(which, func(t *testing.T) {
			r := fixtureRecordStore(t)
			ctx := fixtureContext("one", true)
			meta, err := r.Create(ctx, recordValues(t, "synthetic-key"))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(r.store.path, meta.Reference.ID+".record")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var e recordEnvelope
			if json.Unmarshal(raw, &e) != nil {
				t.Fatal("envelope")
			}
			switch which {
			case "kind":
				e.Kind = "mechanize.vault.v1"
			case "version":
				e.Version = "other-version"
			case "namespace", "foreign-namespace":
				p, _ := auth.FromContext(fixtureContext("other", true))
				e.Namespace = p.Namespace
			case "ciphertext":
				e.Ciphertext[len(e.Ciphertext)-1] ^= 1
			case "tag":
				e.Tag[0] ^= 1
			case "id":
				newID := strings.Repeat("1", 64)
				if err = os.Rename(path, filepath.Join(r.store.path, newID+".record")); err != nil {
					t.Fatal(err)
				}
				meta.Reference.ID = newID
			}
			if which != "id" {
				changed, _ := json.Marshal(e)
				if err = os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = r.Metadata(ctx, meta.Reference); !errors.Is(err, ErrUnavailable) {
				t.Fatal("tampered metadata accepted", err)
			}
			// Foreign header routing must be authenticated before inventory skips it.
			if _, err = r.Inventory(ctx); !errors.Is(err, ErrUnavailable) {
				t.Fatal("tampered inventory accepted", err)
			}
		})
	}
}
func TestRecordFilesystemAndLegacySeparation(t *testing.T) {
	for _, which := range []string{"symlink", "hardlink", "mode", "marker", "unknown", "fifo", "root-mode"} {
		t.Run(which, func(t *testing.T) {
			r := fixtureRecordStore(t)
			ctx := fixtureContext("one", true)
			meta, err := r.Create(ctx, recordValues(t, "key"))
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(r.store.path, meta.Reference.ID+".record")
			switch which {
			case "fifo":
				err = os.Remove(file)
				if err == nil {
					err = unix.Mkfifo(file, 0600)
				}
			case "root-mode":
				err = os.Chmod(r.store.path, 0755)
			case "symlink":
				target := filepath.Join(t.TempDir(), "encrypted")
				if err = os.Rename(file, target); err == nil {
					err = os.Symlink(target, file)
				}
			case "hardlink":
				err = os.Link(file, filepath.Join(t.TempDir(), "alias"))
			case "mode":
				err = os.Chmod(file, 0644)
			case "marker":
				err = os.WriteFile(filepath.Join(r.store.path, recordMarker), []byte("wrong"), 0600)
			case "unknown":
				err = os.WriteFile(filepath.Join(r.store.path, "legacy.enc"), []byte("synthetic"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = r.Inventory(ctx); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unsafe inventory", err)
			}
			if _, err = r.Create(ctx, recordValues(t, "another")); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unsafe write", err)
			}
		})
	}
	old := fixtureStore(t)
	recordStore, err := NewRecordStore(old.path, "fixture-v1", old.cipher)
	if err != nil {
		t.Fatal("empty explicit root", err)
	}
	defer recordStore.Close()
	// A record-format marker makes accidental legacy inventory fail closed.
	if _, err := old.Inventory(fixtureContext("one", true)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("legacy mixed inventory", err)
	}
	legacy := fixtureStore(t)
	if _, err := legacy.Create(fixtureContext("one", true), fixtureBinding().Target, []byte("u"), []byte("p")); err != nil {
		t.Fatal(err)
	}
	if r, err := NewRecordStore(legacy.path, "fixture-v1", legacy.cipher); err == nil {
		r.Close()
		t.Fatal("legacy root accepted")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if r, err := NewRecordStore(dir, "fixture-v1", &Cipher{Keys: fixtureKeys{}}); err == nil {
		r.Close()
		t.Fatal("public root accepted")
	}
}
func TestRecordBinaryPayloadBounds(t *testing.T) {
	v := recordValues(t, "key")
	plain, err := v.take()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	for i := 0; i < len(plain); i++ {
		if _, _, err = parseRecord(plain[:i]); err == nil {
			t.Fatal("truncated payload accepted")
		}
	}
	if _, _, err = parseRecord(append(append([]byte(nil), plain...), 0)); err == nil {
		t.Fatal("trailing payload accepted")
	}
	for _, fields := range [][][2][]byte{nil, {{[]byte(""), []byte("v")}}, {{[]byte("n"), nil}}, {{make([]byte, maxRecordFieldName+1), []byte("v")}}, {{[]byte("n"), make([]byte, maxRecordPlaintext)}}} {
		if v, err := NewRecordValues([]byte("key"), fields); err == nil {
			v.Destroy()
			t.Fatal("invalid bounds accepted")
		}
	}
}

func TestRecordReopenRoundTripAndForeignInventoryDoesNotDecrypt(t *testing.T) {
	r := fixtureRecordStore(t)
	ctx := fixtureContext("one", true)
	key := []byte{0, 1, 255, '/'}
	v, err := NewRecordValues(key, [][2][]byte{{[]byte("token"), []byte{255, 0, 3}}, {[]byte("password"), []byte("synthetic")}})
	if err != nil {
		t.Fatal(err)
	}
	meta, err := r.Create(ctx, v)
	if err != nil {
		t.Fatal(err)
	}
	again, err := NewRecordStore(r.store.path, "fixture-v1", &Cipher{Keys: fixtureKeys{}})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	p, _ := auth.FromContext(ctx)
	loaded, plain, err := again.load(ctx, p.Namespace, meta.Reference.ID)
	if err != nil || loaded != meta {
		t.Fatal("reopen", err)
	}
	gotKey, fields, err := parseRecord(plain)
	if err != nil || !bytes.Equal(gotKey, []byte{0, 1, 255, '/'}) || len(fields) != 2 || !bytes.Equal(fields[0][1], []byte{255, 0, 3}) || string(fields[1][0]) != "password" {
		clear(plain)
		t.Fatal("roundtrip")
	}
	clear(plain)
	spy := &inventorySpyCipher{Cipher: again.store.cipher.(*Cipher)}
	again.store.cipher = spy
	rows, err := again.Inventory(fixtureContext("foreign", true))
	if err != nil || len(rows) != 0 || spy.decryptions != 0 {
		t.Fatal("foreign record decrypted", err)
	}
	if _, err = again.Lookup(fixtureContext("foreign", true), []byte{0, 1, 255, '/'}); !errors.Is(err, ErrMissing) || spy.decryptions != 0 {
		t.Fatal("foreign lookup decrypted", err)
	}
}

func TestRecordConflictAndMissingKeyWipeInputs(t *testing.T) {
	r := fixtureRecordStore(t)
	ctx := fixtureContext("one", true)
	meta, err := r.Create(ctx, recordValues(t, "key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, which := range []string{"conflict", "key-unavailable"} {
		t.Run(which, func(t *testing.T) {
			key, name, value := []byte("key"), []byte("name"), []byte("secret")
			v, err := NewRecordValues(key, [][2][]byte{{name, value}})
			if err != nil {
				t.Fatal(err)
			}
			if which == "key-unavailable" {
				r.store.cipher = &Cipher{Keys: unavailableNativeKeys{}}
			}
			_, err = r.Update(ctx, meta.Reference, strings.Repeat("0", 64), v)
			expected := ErrConflict
			if which == "key-unavailable" {
				expected = ErrUnavailable
			}
			if !errors.Is(err, expected) {
				t.Fatal(err)
			}
			for _, b := range [][]byte{key, name, value} {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Fatal("error input not wiped")
				}
			}
		})
	}
}

func TestRecordRootGitSymlinkAndLockCustody(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(parent, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if r, err := NewRecordStore(filepath.Join(parent, "records"), "fixture-v1", &Cipher{Keys: fixtureKeys{}}); err == nil {
		r.Close()
		t.Fatal("git root accepted")
	}
	clean, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(clean, "link")
	if err = os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if r, err := NewRecordStore(link, "fixture-v1", &Cipher{Keys: fixtureKeys{}}); err == nil {
		r.Close()
		t.Fatal("symlink root accepted")
	}
	r := fixtureRecordStore(t)
	ctx := fixtureContext("one", true)
	if _, err = r.Inventory(ctx); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(r.store.path, ".vault-write.lock")
	if err = os.Link(lock, filepath.Join(t.TempDir(), "lock-alias")); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Create(ctx, recordValues(t, "key")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("hardlinked lock accepted", err)
	}
}

type recordBufferSpy struct {
	*Cipher
	plaintext [][]byte
}

func (s *recordBufferSpy) Encrypt(ctx context.Context, key *kms.Key, b []byte) ([]byte, error) {
	s.plaintext = append(s.plaintext, b)
	return s.Cipher.Encrypt(ctx, key, b)
}
func (s *recordBufferSpy) Decrypt(ctx context.Context, key *kms.Key, b []byte) ([]byte, error) {
	plain, err := s.Cipher.Decrypt(ctx, key, b)
	s.plaintext = append(s.plaintext, plain)
	return plain, err
}
func TestRecordPublicOperationsWipeAllCipherPlaintextBuffers(t *testing.T) {
	r := fixtureRecordStore(t)
	ctx := fixtureContext("one", true)
	spy := &recordBufferSpy{Cipher: r.store.cipher.(*Cipher)}
	r.store.cipher = spy
	check := func() {
		t.Helper()
		for _, b := range spy.plaintext {
			if !bytes.Equal(b, make([]byte, len(b))) {
				t.Fatal("cipher plaintext retained")
			}
		}
		spy.plaintext = nil
	}
	meta, err := r.Create(ctx, recordValues(t, "key"))
	if err != nil {
		t.Fatal(err)
	}
	check()
	if _, err = r.Metadata(ctx, meta.Reference); err != nil {
		t.Fatal(err)
	}
	check()
	if _, err = r.Inventory(ctx); err != nil {
		t.Fatal(err)
	}
	check()
	if _, err = r.Lookup(ctx, []byte("key")); err != nil {
		t.Fatal(err)
	}
	check()
	if _, err = r.Create(ctx, recordValues(t, "key")); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	check()
	updated, err := r.Update(ctx, meta.Reference, meta.Revision, recordValues(t, "renamed"))
	if err != nil {
		t.Fatal(err)
	}
	check()
	if err = r.Delete(ctx, updated.Reference, updated.Revision); err != nil {
		t.Fatal(err)
	}
	check()
}
