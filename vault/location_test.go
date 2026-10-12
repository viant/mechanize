package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGitCheckoutAndWorktreeRefusedBeforeDirectoryCreation(t *testing.T) {
	for _, kind := range []string{"directory", "file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(root, ".git")
			switch kind {
			case "directory":
				err = os.Mkdir(marker, 0700)
			case "file":
				err = os.WriteFile(marker, []byte("gitdir: /not-used"), 0600)
			case "symlink":
				err = os.Symlink("/absent", marker)
			}
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "nested", "vault-data")
			if s, err := NewStore(target, "fixture-v1", &Cipher{Keys: fixtureKeys{}}); err != ErrUnavailable {
				if s != nil {
					s.Close()
				}
				t.Fatal("Git checkout accepted")
			}
			if _, err := os.Lstat(filepath.Join(root, "nested")); !os.IsNotExist(err) {
				t.Fatal("refusal created storage directory")
			}
		})
	}
}
func TestNewGitMarkerBlocksExistingVaultAccess(t *testing.T) {
	s := fixtureStore(t)
	if err := os.Mkdir(filepath.Join(s.path, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx := fixtureContext("one", true)
	target := fixtureBinding().Target
	if _, err := s.Create(ctx, target, []byte("fixture-user"), []byte("fixture-password")); err != ErrUnavailable {
		t.Fatal("write into Git accepted")
	}
	if _, err := s.Lookup(ctx, target); err != ErrUnavailable {
		t.Fatal("read from Git accepted")
	}
	if _, err := os.Lstat(filepath.Join(s.path, ".vault-write.lock")); !os.IsNotExist(err) {
		t.Fatal("refusal created lock")
	}
}
