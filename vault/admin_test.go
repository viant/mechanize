package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
)

func TestNativeVaultCRUDIsRevisionBoundAndReferenceOnly(t *testing.T) {
	s := fixtureStore(t)
	ctx := fixtureContext("admin-fixture", true)
	target := fixtureBinding().Target
	user, pass := []byte("fixture-user-canary"), []byte("fixture-password-canary")
	ref, err := s.Create(ctx, target, user, pass)
	if err != nil || !bytes.Equal(user, make([]byte, len(user))) || !bytes.Equal(pass, make([]byte, len(pass))) {
		t.Fatal("create did not wipe caller buffers", err)
	}
	first, err := s.Metadata(ctx, target)
	if err != nil || first.Reference != ref || len(first.Revision) != 64 {
		t.Fatal("metadata", err)
	}
	raw, err := json.Marshal(first)
	if err != nil || strings.Contains(string(raw), "canary") || strings.Contains(string(raw), "username") || strings.Contains(string(raw), "password") {
		t.Fatal("secret in public metadata")
	}
	if _, err = s.Create(ctx, target, []byte("x"), []byte("y")); !errors.Is(err, ErrConflict) {
		t.Fatal("create overwrote existing entry", err)
	}
	if _, err = s.Update(ctx, target, strings.Repeat("0", 64), []byte("x"), []byte("y")); !errors.Is(err, ErrConflict) {
		t.Fatal("stale update", err)
	}
	updated, err := s.Update(ctx, target, first.Revision, []byte("new-fixture-user"), []byte("new-fixture-password"))
	if err != nil || updated != ref {
		t.Fatal("update", err)
	}
	second, err := s.Metadata(ctx, target)
	if err != nil || second.Revision == first.Revision {
		t.Fatal("revision did not change", err)
	}
	if err = s.Delete(ctx, target, first.Revision); !errors.Is(err, ErrConflict) {
		t.Fatal("stale delete", err)
	}
	if err = s.Delete(ctx, target, second.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Lookup(ctx, target); !errors.Is(err, ErrMissing) {
		t.Fatal("delete did not remove entry", err)
	}
}

func TestAgentsCannotWriteAndOtherIdentityCannotUseRevision(t *testing.T) {
	s := fixtureStore(t)
	target := fixtureBinding().Target
	agent := fixtureContext("one", false)
	human := fixtureContext("one", true)
	u, p := []byte("fixture-user"), []byte("fixture-password")
	if _, err := s.Create(agent, target, u, p); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	if !bytes.Equal(u, make([]byte, len(u))) || !bytes.Equal(p, make([]byte, len(p))) {
		t.Fatal("unauthorized buffers retained")
	}
	if _, err := s.Create(human, target, []byte("fixture-user"), []byte("fixture-password")); err != nil {
		t.Fatal(err)
	}
	meta, _ := s.Metadata(human, target)
	if _, err := s.Update(agent, target, meta.Revision, []byte("x"), []byte("y")); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	if err := s.Delete(agent, target, meta.Revision); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	if err := s.Delete(fixtureContext("other", true), target, meta.Revision); !errors.Is(err, ErrMissing) {
		t.Fatal("cross-user delete", err)
	}
	if _, err := s.Metadata(context.Background(), target); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal(err)
	}
	if _, err := s.Lookup(human, target); err != nil {
		t.Fatal("entry damaged", err)
	}
}
