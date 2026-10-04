package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestConcurrentRenewalIsRejectedWithoutReplacingToken(t *testing.T) {
	path, c := fixture(t)
	before, _ := private(c.Credential.URL)
	release, err := renewalLock(filepath.Dir(c.Credential.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := renew(context.Background(), path, true); err == nil {
		t.Fatal("competing renewal admitted")
	}
	after, _ := private(c.Credential.URL)
	if !bytes.Equal(before, after) {
		t.Fatal("busy renewal changed token")
	}
	release()
	if result, err := renew(context.Background(), path, true); err != nil || !result.Renewed {
		t.Fatalf("released renewal unavailable: %v", err)
	}
}

func TestRenewalLockRejectsUnsafePaths(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "shared-file", "shared-directory"} {
		t.Run(kind, func(t *testing.T) {
			_, c := fixture(t)
			dir := filepath.Dir(c.Credential.URL)
			lock := filepath.Join(dir, ".renew.lock")
			switch kind {
			case "symlink":
				if err := os.Symlink(c.Credential.URL, lock); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(c.Credential.URL, lock); err != nil {
					t.Fatal(err)
				}
			case "shared-file":
				if err := os.WriteFile(lock, nil, 0644); err != nil {
					t.Fatal(err)
				}
			case "shared-directory":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			}
			if release, err := renewalLock(dir); err == nil {
				release()
				t.Fatal("unsafe lock accepted")
			}
		})
	}
}

func TestReadableOwnedDirectoryAndCanceledRenewal(t *testing.T) {
	path, c := fixture(t)
	before, _ := private(c.Credential.URL)
	if err := os.Chmod(filepath.Dir(c.Credential.URL), 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := renew(ctx, path, true); err == nil {
		t.Fatal("canceled renewal admitted")
	}
	after, _ := private(c.Credential.URL)
	if !bytes.Equal(before, after) {
		t.Fatal("cancellation changed token")
	}
	if r, err := renew(context.Background(), path, true); err != nil || !r.Renewed {
		t.Fatalf("owned non-writable directory rejected: %v", err)
	}
}
