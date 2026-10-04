package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fixtureKeys struct{}

func (fixtureKeys) Resolve(context.Context, string) ([]byte, error) {
	return bytes.Repeat([]byte{23}, 32), nil
}
func fixtureContext(subject string, human bool) context.Context {
	p, _ := auth.NewPrincipal("fixture", "", subject, []string{"consent:admin"})
	ctx := auth.WithPrincipal(context.Background(), p)
	if human {
		ctx, _ = auth.WithNativeHuman(ctx)
	}
	return ctx
}
func fixtureStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(root, "fixture-v1", &Cipher{Keys: fixtureKeys{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func fixtureBinding() Binding {
	return Binding{SessionID: "session", DocumentID: "document", NavigationID: "navigation", Target: Target{Origin: "https://example.test", Account: "business"}}
}

func TestMissingNativeInputStoresEncryptedAndResumesOnce(t *testing.T) {
	s := fixtureStore(t)
	ctx := fixtureContext("one", false)
	human := fixtureContext("one", true)
	b := fixtureBinding()
	var request Request
	resumeCount := 0
	m, _ := NewManager(s, Hooks{Present: func(_ context.Context, r Request) error { request = r; return nil }, Fresh: func(_ context.Context, b Binding) (Binding, error) { return b, nil }, Resume: func(ctx context.Context, b Binding, r Reference) error {
		resumeCount++
		return s.Consume(ctx, b.Target, r, func(c Credentials) error {
			return c.WithBytes(func(u, p []byte) error {
				if string(u) != "private-user" || string(p) != "private-password" {
					t.Fatal("credential changed")
				}
				return nil
			})
		})
	}})
	if _, err := m.Ensure(ctx, b); !errors.Is(err, ErrPending) || request.ID == "" {
		t.Fatal(err)
	}
	if _, err := m.Ensure(ctx, b); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	u, p := []byte("private-user"), []byte("private-password")
	if err := m.Submit(human, request.ID, u, p); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(u, make([]byte, len(u))) || !bytes.Equal(p, make([]byte, len(p))) {
		t.Fatal("submit did not clear buffers")
	}
	if err := m.Submit(human, request.ID, []byte("x"), []byte("y")); !errors.Is(err, ErrStale) {
		t.Fatal("submission replay accepted")
	}
	if resumeCount != 1 {
		t.Fatal(resumeCount)
	}
	ref, err := m.Ensure(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(ref)
	if bytes.Contains(public, []byte("private")) || !bytes.Contains(public, []byte("resourceURL")) {
		t.Fatal("secret in public result")
	}
	pctx, _ := auth.FromContext(ctx)
	file := filepath.Join(s.root.Name(), identifier(pctx.Namespace, b.Target)+".enc")
	encrypted, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("private-user")) || bytes.Contains(encrypted, []byte("private-password")) {
		t.Fatal("plaintext on disk")
	}
	if _, err := s.Lookup(fixtureContext("other", false), b.Target); !errors.Is(err, ErrMissing) {
		t.Fatal("namespace leak")
	}
	if err := s.Consume(ctx, Target{Origin: "https://other.test", Account: "business"}, ref, func(Credentials) error { t.Fatal("cross-origin consume"); return nil }); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
	var e envelope
	json.Unmarshal(encrypted, &e)
	e.Ciphertext[len(e.Ciphertext)-1] ^= 1
	corrupted, _ := json.Marshal(e)
	os.WriteFile(file, corrupted, 0600)
	if _, err := s.Lookup(ctx, b.Target); !errors.Is(err, ErrUnavailable) {
		t.Fatal("tampering accepted")
	}
}

func TestAgentCannotSubmitAndNavigationFailsClosed(t *testing.T) {
	s := fixtureStore(t)
	ctx := fixtureContext("one", false)
	human := fixtureContext("one", true)
	b := fixtureBinding()
	current := b
	var request Request
	m, _ := NewManager(s, Hooks{Present: func(_ context.Context, r Request) error { request = r; return nil }, Fresh: func(context.Context, Binding) (Binding, error) { return current, nil }, Resume: func(context.Context, Binding, Reference) error { t.Fatal("stale document resumed"); return nil }})
	m.Ensure(ctx, b)
	if err := m.Submit(ctx, request.ID, []byte("user"), []byte("password")); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	if err := m.Submit(fixtureContext("other", true), request.ID, []byte("user"), []byte("password")); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	current.NavigationID = "different"
	if err := m.Submit(human, request.ID, []byte("user"), []byte("password")); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	if _, err := s.Lookup(ctx, b.Target); !errors.Is(err, ErrMissing) {
		t.Fatal("stale request stored")
	}
}

func TestRootSymlinkAndInvalidTargetsRejected(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(dir, "link")
	os.Symlink(t.TempDir(), alias)
	if _, err := NewStore(alias, "fixture-v1", &Cipher{Keys: fixtureKeys{}}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("symlink root accepted")
	}
	for _, origin := range []string{"http://example.test", "https://example.test/", "https://example.test?", "https://example.test#x", "https://user@example.test", "https://Example.test", "https://example.test:443", "https://example.test."} {
		if (Target{Origin: origin, Account: "a"}).Validate() == nil {
			t.Fatal("invalid origin accepted", origin)
		}
	}
	if _, err := json.Marshal(Credentials{password: []byte("private")}); err == nil {
		t.Fatal("credential serialization accepted")
	}
}

func TestScyEnvKeysAndChildSanitization(t *testing.T) {
	t.Setenv("MECHANIZE_FIXTURE_VAULT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32)))
	keys, err := NewScyEnvKeys(map[string]string{"v1": "MECHANIZE_FIXTURE_VAULT_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := keys.Resolve(context.Background(), "v1")
	if err != nil || len(b) != 32 || b[0] != 42 {
		t.Fatal("Scy env lookup failed", err)
	}
	clear(b)
	if _, err = keys.Resolve(context.Background(), "unknown"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unenrolled key accepted")
	}
	env := keys.ChildEnvironment([]string{"PATH=/bin", "MECHANIZE_FIXTURE_VAULT_KEY=private", "LANG=en_US"})
	if len(env) != 2 || env[0] != "PATH=/bin" || env[1] != "LANG=en_US" {
		t.Fatal("child environment retained key")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if strings.Contains(fmt.Sprintf(verb, Credentials{username: []byte("private"), password: []byte("private")}), "private") {
			t.Fatal("credential formatted")
		}
	}
}

func TestExplicitLegacyScyEnvReference(t *testing.T) {
	t.Setenv("MECHANIZE_FIXTURE_LEGACY_KEY", "random-fixture-key-material-32b!!")
	file := filepath.Join(t.TempDir(), "fixture.json")
	resource := scy.NewResource(&cred.Basic{}, file, "blowfish://env/MECHANIZE_FIXTURE_LEGACY_KEY")
	if err := scy.New().Store(context.Background(), scy.NewSecret(&cred.Basic{Username: "fixture-user", Password: "fixture-password"}, resource)); err != nil {
		t.Fatal(err)
	}
	ctx := fixtureContext("one", false)
	p, _ := auth.FromContext(ctx)
	target := fixtureBinding().Target
	r, err := NewLegacyResolver([]LegacyEnrollment{{Namespace: p.Namespace, Target: target, Resource: *resource}})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := r.Reference(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ref.ResourceURL, "LEGACY") || strings.Contains(ref.ResourceURL, file) {
		t.Fatal("key/file locator exposed")
	}
	if err = r.Consume(ctx, target, ref, func(c Credentials) error {
		return c.WithBytes(func(u, p []byte) error {
			if string(u) != "fixture-user" || string(p) != "fixture-password" {
				t.Fatal("Scy basic decode failed")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err = r.Consume(ctx, target, ref, func(Credentials) error { return errors.New("private-backend-error") }); err != ErrUnavailable {
		t.Fatal("private backend error escaped")
	}
	if _, err = r.Reference(fixtureContext("other", false), target); err != ErrMissing {
		t.Fatal("legacy cross-user lookup accepted")
	}
	resource.Key = "blowfish://default"
	if _, err = NewLegacyResolver([]LegacyEnrollment{{Namespace: p.Namespace, Target: target, Resource: *resource}}); err != ErrScope {
		t.Fatal("public default enrolled")
	}
}
