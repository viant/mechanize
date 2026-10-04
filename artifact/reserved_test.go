package artifact

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
)

func TestReservedArtifactWriteInspectDuplicateAndRotation(t *testing.T) {
	store, _ := fixture(t, 1024*1024, 8*1024*1024)
	ctx, namespace := scoped(t, "reserved-owner")
	id := strings.Repeat("a", 32)
	original := []byte("private reserved review evidence")
	ref, err := store.PutReserved(ctx, namespace, id, "fixture-v1", "application/vnd.viant.workflow-review+json", bytes.NewReader(original))
	if err != nil || ref.ID != id || ref.KeyReference != "fixture-v1" {
		t.Fatal("reserved write failed", err)
	}
	inspected, payload, err := store.InspectReserved(ctx, namespace, id, "fixture-v1")
	if err != nil || inspected != ref || !bytes.Equal(payload, original) {
		t.Fatal("metadata-free reserved inspection failed", err)
	}
	encrypted, err := store.root.ReadFile(filepath.Join(namespace, id))
	if err != nil || !bytes.HasPrefix(encrypted, []byte("MAE1")) || bytes.Contains(encrypted, original) {
		t.Fatal("reserved bytes not encrypted", err)
	}
	payload[0] = 0
	_, payload, err = store.InspectReserved(ctx, namespace, id, "fixture-v1")
	if err != nil || !bytes.Equal(payload, original) {
		t.Fatal("caller mutated immutable reserved bytes", err)
	}
	for _, next := range []string{string(original), "different evidence"} {
		duplicate, err := store.PutReserved(ctx, namespace, id, "fixture-v2", "text/plain", strings.NewReader(next))
		if !errors.Is(err, ErrExists) || duplicate != (data.ArtifactReference{}) {
			t.Fatal("duplicate reserved ID adopted/replaced bytes", err)
		}
	}
	after, err := store.root.ReadFile(filepath.Join(namespace, id))
	if err != nil || !bytes.Equal(after, encrypted) {
		t.Fatal("duplicate altered encrypted file", err)
	}
	rotatedConfig := store.config
	rotatedConfig.SourceKeyReference = "fixture-v2"
	rotated, err := New(rotatedConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Close()
	old, oldBytes, err := rotated.InspectReserved(ctx, namespace, id, "fixture-v1")
	if err != nil || old != ref || !bytes.Equal(oldBytes, original) {
		t.Fatal("explicit old key failed after rotation", err)
	}
	if _, _, err = rotated.InspectReserved(ctx, namespace, id, "fixture-v2"); !errors.Is(err, ErrCorrupt) {
		t.Fatal("wrong explicit key silently fell back", err)
	}
	if _, _, err = rotated.InspectReserved(ctx, namespace, id, "unregistered-version"); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatal("unapproved key accepted or guessed", err)
	}
}

func TestReservedArtifactScopePathsSymlinksLimitsAndCancellation(t *testing.T) {
	store, _ := fixture(t, 64, 8*1024)
	ctx, namespace := scoped(t, "reserved-alice")
	other, otherNamespace := scoped(t, "reserved-bob")
	id := strings.Repeat("b", 32)
	ref, err := store.PutReserved(ctx, namespace, id, "fixture-v1", "text/plain", strings.NewReader("reserved fixture"))
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "../escape", "/tmp/file", "https://fixture/file", strings.Repeat("B", 32)} {
		if _, err := store.PutReserved(ctx, namespace, invalid, "fixture-v1", "text/plain", strings.NewReader("private")); !errors.Is(err, ErrCorrupt) {
			t.Fatal("invalid reserved path accepted", err)
		}
		if _, _, err := store.InspectReserved(ctx, namespace, invalid, "fixture-v1"); !errors.Is(err, ErrCorrupt) {
			t.Fatal("invalid inspect path accepted", err)
		}
	}
	if _, err = store.PutReserved(other, namespace, strings.Repeat("c", 32), "fixture-v1", "text/plain", strings.NewReader("unowned")); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("cross-user reserved write admitted", err)
	}
	if _, _, err = store.InspectReserved(other, namespace, id, "fixture-v1"); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("cross-user reserved inspection admitted", err)
	}
	if _, err = store.PutReserved(ctx, otherNamespace, strings.Repeat("c", 32), "fixture-v1", "text/plain", strings.NewReader("unowned")); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("caller namespace overrode verified owner", err)
	}
	principal, _ := auth.FromContext(ctx)
	if _, _, err = store.InspectReserved(auth.WithPrincipal(context.Background(), principal), namespace, id, "fixture-v1"); err == nil {
		t.Fatal("unscoped reserved inspection admitted")
	}
	if _, err = store.PutReserved(ctx, namespace, strings.Repeat("d", 32), "fixture-v1", "text/plain", bytes.NewReader(make([]byte, 65))); !errors.Is(err, ErrLimit) {
		t.Fatal("reserved write exceeded byte bound", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = store.PutReserved(canceled, namespace, strings.Repeat("d", 32), "fixture-v1", "text/plain", strings.NewReader("private")); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled reserved write proceeded", err)
	}
	if _, _, err = store.InspectReserved(canceled, namespace, id, "fixture-v1"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled reserved inspect proceeded", err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	if err = os.WriteFile(target, []byte("outside-private"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := store.root.OpenRoot(namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	linkID := strings.Repeat("e", 32)
	if err = root.Symlink(target, linkID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.InspectReserved(ctx, namespace, linkID, "fixture-v1"); !errors.Is(err, ErrCorrupt) {
		t.Fatal("symlink reserved entry read outside scope", err)
	}
	if _, err = store.PutReserved(ctx, namespace, linkID, "fixture-v1", "text/plain", strings.NewReader("replace")); !errors.Is(err, ErrExists) {
		t.Fatal("occupied symlink slot overwritten", err)
	}
	if _, err = store.Read(ctx, namespace, ref); err != nil {
		t.Fatal("unrelated legitimate reserved bytes changed", err)
	}
}

func overwriteReservedTestPayload(t *testing.T, store *Store, ctx context.Context, namespace, id, key string, value payload) {
	t.Helper()
	aead, err := store.aead(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	encrypted := append([]byte("MAE1"), nonce...)
	encrypted = aead.Seal(encrypted, nonce, plain, associated(namespace, id, key))
	root, err := store.root.OpenRoot(namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := root.OpenFile(id, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(encrypted); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReservedArtifactAuthenticatesEmbeddedReferenceAndCiphertext(t *testing.T) {
	store, _ := fixture(t, 1024, 16*1024)
	ctx, namespace := scoped(t, "reserved-integrity")
	id := strings.Repeat("f", 32)
	for _, test := range []struct {
		name   string
		change func(*payload)
	}{
		{"id", func(v *payload) { v.Reference.ID = strings.Repeat("a", 32) }},
		{"key", func(v *payload) { v.Reference.KeyReference = "fixture-v2" }},
		{"hash", func(v *payload) { v.Reference.ContentHash = strings.Repeat("0", 64) }},
		{"size", func(v *payload) { v.Reference.SizeBytes++ }},
		{"mime", func(v *payload) { v.Reference.MediaType = "not a MIME" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Each test uses an authenticated but internally inconsistent fixture to
			// prove inspection validates embedded fields beyond the encryption tag.
			body := []byte("fixture-integrity")
			ref, err := store.Put(ctx, namespace, "text/plain", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			value := payload{Reference: ref, Bytes: body}
			value.Reference.ID = id
			test.change(&value)
			overwriteReservedTestPayload(t, store, ctx, namespace, id, "fixture-v1", value)
			got, b, err := store.InspectReserved(ctx, namespace, id, "fixture-v1")
			if !errors.Is(err, ErrCorrupt) || got != (data.ArtifactReference{}) || b != nil {
				t.Fatal("inconsistent authenticated payload exported", err)
			}
		})
	}
	// Independently corrupt a valid sealed artifact; no metadata or plaintext is
	// exposed even when the reserved ID/key are known.
	validID := strings.Repeat("1", 32)
	_, err := store.PutReserved(ctx, namespace, validID, "fixture-v1", "text/plain", strings.NewReader("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := store.root.OpenRoot(namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	encrypted, err := root.ReadFile(validID)
	if err != nil {
		t.Fatal(err)
	}
	encrypted[len(encrypted)-1] ^= 1
	file, err := root.OpenFile(validID, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.Write(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if _, b, err := store.InspectReserved(ctx, namespace, validID, "fixture-v1"); !errors.Is(err, ErrCorrupt) || b != nil {
		t.Fatal("corrupt ciphertext exported", err)
	}
}

func TestReservedArtifactConcurrentWritersHaveOneImmutableWinner(t *testing.T) {
	store, _ := fixture(t, 1024, 32*1024)
	ctx, namespace := scoped(t, "reserved-concurrency")
	second, err := New(store.config)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	id := strings.Repeat("2", 32)
	type result struct {
		ref  data.ArtifactReference
		body string
		err  error
	}
	results := make(chan result, 8)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			body := strings.Repeat(string(rune('a'+i)), i+1)
			writer := store
			if i%2 == 1 {
				writer = second
			}
			ref, err := writer.PutReserved(ctx, namespace, id, "fixture-v1", "text/plain", strings.NewReader(body))
			results <- result{ref: ref, body: body, err: err}
		}(i)
	}
	close(start)
	workers.Wait()
	close(results)
	winners := 0
	var winner result
	for got := range results {
		if got.err == nil {
			winners++
			winner = got
		} else if !errors.Is(got.err, ErrExists) {
			t.Fatal("concurrent immutable write returned unexpected error", got.err)
		}
	}
	if winners != 1 {
		t.Fatal("reserved slot did not have exactly one winner", winners)
	}
	ref, body, err := store.InspectReserved(ctx, namespace, id, "fixture-v1")
	if err != nil || ref != winner.ref || string(body) != winner.body {
		t.Fatal("losing writer replaced/adopted winning payload", err)
	}
}
