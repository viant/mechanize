package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/scy/kms"
)

func localKeyFixture(t *testing.T) (*LocalKeyProvisioner, context.Context, context.Context) {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	p, e := NewLocalKeyProvisioner(filepath.Join(root, "keys"), "fixture-master", "fixture-v1")
	if e != nil {
		t.Fatal(e)
	}
	actor, e := auth.NewPrincipal("fixture", "", "local-owner", []string{"desktop:control", "consent:admin"})
	if e != nil {
		t.Fatal(e)
	}
	actor.ClientID = "fixture-client"
	ctx := auth.WithPrincipal(context.Background(), actor)
	native, e := auth.WithNativeHuman(ctx)
	if e != nil {
		t.Fatal(e)
	}
	p.entropy = bytes.NewReader(bytes.Repeat([]byte{19}, 64))
	return p, ctx, native
}
func TestLocalScyKeyNativeSetupAndAuthenticatedCipherSurviveRestart(t *testing.T) {
	p, ctx, native := localKeyFixture(t)
	if p.Ready(native) == nil {
		t.Fatal("missing key ready")
	}
	if _, e := p.Ensure(ctx, func(context.Context) error { return nil }); !errors.Is(e, auth.ErrUnauthorized) {
		t.Fatal("MCP actor provisioned key")
	}
	checks := 0
	ref, e := p.Ensure(native, func(context.Context) error { checks++; return nil })
	if e != nil || checks != 1 || ref != "mechanize-local-key://native/fixture-master" {
		t.Fatal("native setup failed")
	}
	material, e := os.ReadFile(filepath.Join(p.directory, p.alias+".json"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Ensure(native, func(context.Context) error { t.Fatal("existing key requested replacement"); return nil }); e != nil {
		t.Fatal("existing key unavailable")
	}
	current, _ := os.ReadFile(filepath.Join(p.directory, p.alias+".json"))
	if !bytes.Equal(current, material) {
		t.Fatal("existing master key changed")
	}
	c := &Cipher{Keys: p}
	plain := []byte("synthetic-local-secret-canary")
	key := &kms.Key{Raw: p.version, Path: "fixture/record"}
	encrypted, e := c.Encrypt(ctx, key, plain)
	if e != nil || bytes.Contains(encrypted, plain) || bytes.Contains(material, plain) {
		t.Fatal("credential was not encrypted")
	}
	restarted, e := NewLocalKeyProvisioner(p.directory, p.alias, p.version)
	if e != nil || restarted.Ready(native) != nil {
		t.Fatal("local key lost across runtime restart")
	}
	decoded, e := (&Cipher{Keys: restarted}).Decrypt(ctx, key, encrypted)
	if e != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("restarted cipher could not decrypt")
	}
	clear(decoded)
	if _, e = (&Cipher{Keys: restarted}).Decrypt(ctx, &kms.Key{Raw: p.version, Path: "other/record"}, encrypted); e == nil {
		t.Fatal("scope substitution accepted")
	}
	encrypted[len(encrypted)-1] ^= 1
	if _, e = c.Decrypt(ctx, key, encrypted); e == nil {
		t.Fatal("tampering accepted")
	}
	if _, e = p.Resolve(ctx, "unconfigured-version"); e == nil {
		t.Fatal("unconfigured key version accepted")
	}
	if _, e = p.Resolve(context.Background(), p.version); e == nil {
		t.Fatal("anonymous key resolution accepted")
	}
}
func TestLocalScyKeyRefusesUnsafeCustodyAndReplacement(t *testing.T) {
	for _, mode := range []string{"veto", "permissions", "symlink", "hardlink", "malformed", "duplicateField", "lockSymlink", "rootPermissions"} {
		t.Run(mode, func(t *testing.T) {
			p, ctx, native := localKeyFixture(t)
			path := filepath.Join(p.directory, p.alias+".json")
			if mode == "veto" {
				if _, e := p.Ensure(native, func(context.Context) error { return ErrUnavailable }); e == nil {
					t.Fatal("missing-key ciphertext veto ignored")
				}
				if _, e := os.Lstat(path); !os.IsNotExist(e) {
					t.Fatal("veto created key")
				}
				return
			}
			if _, e := p.Ensure(native, func(context.Context) error { return nil }); e != nil {
				t.Fatal(e)
			}
			original, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "permissions":
				os.Chmod(path, 0644)
			case "symlink":
				os.Rename(path, path+".retained")
				os.Symlink(path+".retained", path)
			case "hardlink":
				os.Link(path, path+".linked")
			case "malformed":
				os.WriteFile(path, []byte(`{"key":"invalid"}`), 0600)
			case "duplicateField":
				os.WriteFile(path, append(append([]byte{}, original[:len(original)-1]...), append([]byte(","), original[1:]...)...), 0600)
			case "lockSymlink":
				os.Remove(filepath.Join(p.directory, ".key-write.lock"))
				os.Symlink(path, filepath.Join(p.directory, ".key-write.lock"))
			case "rootPermissions":
				os.Chmod(p.directory, 0755)
			}
			if mode != "lockSymlink" {
				if _, e = p.Resolve(ctx, p.version); e == nil {
					t.Fatal("unsafe key custody admitted")
				}
			}
			before, _ := os.ReadFile(path)
			if _, e = p.Ensure(native, func(context.Context) error { t.Fatal("unsafe existing key replaced"); return nil }); e == nil {
				t.Fatal("unsafe existing key accepted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("refusal changed existing key")
			}
		})
	}
}
func TestLocalScyKeyRefusesGitAndUntrustedReferences(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Mkdir(filepath.Join(root, ".git"), 0700)
	if _, e = NewLocalKeyProvisioner(filepath.Join(root, "keys"), "master", "v1"); e == nil {
		t.Fatal("repository key custody admitted")
	}
	for _, alias := range []string{"../key", "key/path", "key?value", "", "key.json"} {
		if _, e := LocalKeyReference(alias); e == nil {
			t.Fatal("untrusted reference admitted")
		}
	}
}
