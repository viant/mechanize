package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHardLinkedCiphertextRefusedWithoutDisclosure(t *testing.T) {
	s := fixtureStore(t)
	ctx := fixtureContext("one", true)
	target := fixtureBinding().Target
	if _, err := s.Create(ctx, target, []byte("synthetic-user"), []byte("synthetic-password")); err != nil {
		t.Fatal(err)
	}
	ns, id, err := scoped(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(s.path, "unexpected-alias")
	if err = os.Link(filepath.Join(s.path, id+".enc"), alias); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Lookup(ctx, target); err != ErrUnavailable {
		t.Fatal("hard-linked ciphertext accepted")
	}
	called := false
	if err = s.Consume(ctx, target, Reference{ResourceURL: reference(ns, target)}, func(Credentials) error { called = true; return nil }); err != ErrUnavailable || called {
		t.Fatal("hard-linked credential consumed")
	}
	if err = os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Lookup(ctx, target); err != nil {
		t.Fatal("original entry damaged")
	}
}

func TestHardLinkedAdministrationLockRefused(t *testing.T) {
	s := fixtureStore(t)
	lock := filepath.Join(s.path, ".vault-write.lock")
	if err := os.WriteFile(lock, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(lock, filepath.Join(s.path, "lock-alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(fixtureContext("one", true), fixtureBinding().Target, []byte("synthetic-user"), []byte("synthetic-password")); err != ErrUnavailable {
		t.Fatal("hard-linked lock accepted")
	}
}
