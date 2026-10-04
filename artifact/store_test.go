package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/scy"
	"golang.org/x/sys/unix"
)

func scoped(t *testing.T, subject string) (context.Context, string) {
	t.Helper()
	p, err := auth.NewPrincipal("fixture-issuer", "fixture-tenant", subject, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := data.WithScope(auth.WithPrincipal(context.Background(), p), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, p.Namespace
}
func fixture(t *testing.T, max, quota int64) (*Store, string) {
	t.Helper()
	temporary, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(temporary, "artifacts")
	keyFile := filepath.Join(t.TempDir(), "key.json")
	key := bytes.Repeat([]byte{17}, 32)
	encoded, _ := json.Marshal(map[string][]byte{"key": key})
	if err := os.WriteFile(keyFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewScyResolver(map[string]scy.Resource{"fixture-v1": {URL: keyFile}, "fixture-v2": {URL: keyFile}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(Config{Root: root, SourceKeyReference: "fixture-v1", Keys: resolver, MaxBytes: max, NamespaceQuotaBytes: quota})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store, keyFile
}
func TestEncryptedScopedArtifacts(t *testing.T) {
	store, _ := fixture(t, 4096, 32768)
	ctx, ns := scoped(t, "alice")
	other, otherNS := scoped(t, "bob")
	content := "fixture secret snapshot metadata: employee-document-title"
	ref, err := store.Put(ctx, ns, "application/json", strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(store.config.Root, ns, ref.ID))
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{content, "application/json", ref.ContentHash, "fixture-v1"} {
		if bytes.Contains(raw, []byte(plain)) {
			t.Fatalf("plaintext persisted: %s", plain)
		}
	}
	actual, err := store.Read(ctx, ns, ref)
	if err != nil || string(actual) != content {
		t.Fatalf("read: %s %v", actual, err)
	}
	if err = store.Verify(ctx, ns, ref); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Read(other, ns, ref); err == nil {
		t.Fatal("cross-owner read allowed")
	}
	if _, err = store.Put(other, ns, "text/plain", strings.NewReader("no")); err == nil {
		t.Fatal("cross-owner write allowed")
	}
	// Even a physical cross-namespace copy cannot authenticate its owner AAD.
	if err = os.Mkdir(filepath.Join(store.config.Root, otherNS), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(store.config.Root, otherNS, ref.ID), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Read(other, otherNS, ref); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("copied artifact: %v", err)
	}
	unauthed, _ := data.WithScope(context.Background(), data.Scope{Namespace: ns})
	if _, err = store.Read(unauthed, ns, ref); err == nil {
		t.Fatal("scope alone authorized read")
	}
	forged := ref
	forged.ID = "../../key.json"
	if _, err = store.Read(ctx, ns, forged); err == nil {
		t.Fatal("path traversal allowed")
	}
	for _, change := range []func(*data.ArtifactReference){func(r *data.ArtifactReference) { r.SizeBytes++ }, func(r *data.ArtifactReference) { r.MediaType = "text/plain" }, func(r *data.ArtifactReference) { r.ContentHash = strings.Repeat("0", 64) }, func(r *data.ArtifactReference) { r.KeyReference = "fixture-v2" }, func(r *data.ArtifactReference) { r.KeyReference = "untrusted://caller" }} {
		forged = ref
		change(&forged)
		if err = store.Verify(ctx, ns, forged); err == nil {
			t.Fatal("forged metadata verified")
		}
	}
	info, _ := os.Stat(filepath.Join(store.config.Root, ns))
	if info.Mode().Perm() != 0700 {
		t.Fatal("namespace permission")
	}
	info, _ = os.Stat(filepath.Join(store.config.Root, ns, ref.ID))
	if info.Mode().Perm() != 0600 {
		t.Fatal("file permission")
	}
}
func TestTamperedTruncatedAndKeyUnavailable(t *testing.T) {
	store, keyFile := fixture(t, 4096, 32768)
	ctx, ns := scoped(t, "alice")
	ref, err := store.Put(ctx, ns, "text/plain", strings.NewReader("private fixture"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.config.Root, ns, ref.ID)
	original, _ := os.ReadFile(path)
	for _, content := range [][]byte{original[:8], append([]byte(nil), original...)} {
		if len(content) > 8 {
			content[len(content)-1] ^= 1
		}
		if err = os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = store.Read(ctx, ns, ref); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("corruption: %v", err)
		}
	}
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Read(ctx, ns, ref); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("missing key read: %v", err)
	}
	if _, err = store.Put(ctx, ns, "text/plain", strings.NewReader("no plaintext fallback")); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("missing key write: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(store.config.Root, ns))
	if len(entries) != 1 {
		t.Fatal("key failure persisted file")
	}
}
func TestSymlinkDenial(t *testing.T) {
	store, _ := fixture(t, 4096, 32768)
	ctx, ns := scoped(t, "alice")
	ref, err := store.Put(ctx, ns, "text/plain", strings.NewReader("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.config.Root, ns, ref.ID)
	outside := filepath.Join(t.TempDir(), "outside")
	if err = os.Rename(path, outside); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Read(ctx, ns, ref); err == nil {
		t.Fatal("file symlink read")
	}
	if _, err = store.Put(ctx, ns, "text/plain", strings.NewReader("fixture")); err == nil {
		t.Fatal("unsafe namespace entry accepted")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(store.config.Root, ns)); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(t.TempDir(), filepath.Join(store.config.Root, ns)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Put(ctx, ns, "text/plain", strings.NewReader("fixture")); err == nil {
		t.Fatal("namespace symlink allowed")
	}
	rootLink := filepath.Join(t.TempDir(), "linked-root")
	os.Symlink(store.config.Root, rootLink)
	if _, err = New(Config{Root: rootLink, Keys: store.config.Keys, SourceKeyReference: "fixture-v1", MaxBytes: 4096, NamespaceQuotaBytes: 32768}); err == nil {
		t.Fatal("root symlink allowed")
	}
}
func TestLimitsCancelAndNoStagingLeak(t *testing.T) {
	store, _ := fixture(t, 8, 450)
	ctx, ns := scoped(t, "alice")
	if _, err := store.Put(ctx, ns, "text/plain", strings.NewReader("123456789")); !errors.Is(err, ErrLimit) {
		t.Fatalf("size: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.Put(cancelled, ns, "text/plain", strings.NewReader("short")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	first, err := store.Put(ctx, ns, "text/plain", strings.NewReader("12345678"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Put(ctx, ns, "text/plain", strings.NewReader("12345678")); !errors.Is(err, ErrLimit) {
		t.Fatalf("quota: %v", err)
	}
	if err = store.Verify(ctx, ns, first); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(store.config.Root, ns))
	if len(entries) != 1 || entries[0].Name() != first.ID {
		t.Fatal("failed write staging leak")
	}
	// Contended process-wide quota locks are cancellable.
	directory, err := os.Open(filepath.Join(store.config.Root, ns))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err = unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(directory.Fd()), unix.LOCK_UN)
	deadline, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	if _, err = store.Put(deadline, ns, "text/plain", strings.NewReader("fixture")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock cancel: %v", err)
	}
}

func TestKeyRotationAndImmutableIdentity(t *testing.T) {
	store, _ := fixture(t, 4096, 32768)
	ctx, ns := scoped(t, "alice")
	ref, err := store.Put(ctx, ns, "text/plain", strings.NewReader("version one"))
	if err != nil {
		t.Fatal(err)
	}
	next := store.config
	next.SourceKeyReference = "fixture-v2"
	rotated, err := New(next)
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Close()
	if err = rotated.Verify(ctx, ns, ref); err != nil {
		t.Fatal("rotation lost configured historical key", err)
	}
	current, err := rotated.Put(ctx, ns, "text/plain", strings.NewReader("version two"))
	if err != nil {
		t.Fatal(err)
	}
	if current.KeyReference != "fixture-v2" {
		t.Fatal("wrong write key version")
	}
	old, _ := os.ReadFile(filepath.Join(store.config.Root, ns, ref.ID))
	moved := ref
	moved.ID = strings.Repeat("b", 32)
	if err = os.WriteFile(filepath.Join(store.config.Root, ns, moved.ID), old, 0600); err != nil {
		t.Fatal(err)
	}
	if err = store.Verify(ctx, ns, moved); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("identity not authenticated: %v", err)
	}
}

func TestQuotaAcrossStoreInstances(t *testing.T) {
	store, _ := fixture(t, 8, 450)
	second, err := New(store.config)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ctx, ns := scoped(t, "alice")
	results := make(chan error, 2)
	for _, instance := range []*Store{store, second} {
		go func(s *Store) { _, err := s.Put(ctx, ns, "text/plain", strings.NewReader("12345678")); results <- err }(instance)
	}
	successes, limits := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrLimit) {
			limits++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || limits != 1 {
		t.Fatalf("quota allocations: success=%d limit=%d", successes, limits)
	}
}
