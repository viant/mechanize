package vault

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPinnedConsumptionRefusesChangedCredential(t *testing.T) {
	s := fixtureStore(t)
	human := fixtureContext("selected", true)
	agent := fixtureContext("selected", false)
	target := fixtureBinding().Target
	ref, err := s.Create(human, target, []byte("fixture-user"), []byte("fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := s.Metadata(human, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Update(human, target, meta.Revision, []byte("new-user"), []byte("new-password")); err != nil {
		t.Fatal(err)
	}
	if err = s.ConsumeRevision(agent, target, ref, meta.Revision, func(Credentials) error { t.Fatal("changed secret delivered"); return nil }); !errors.Is(err, ErrConflict) {
		t.Fatal("selected revision was not enforced")
	}
}

func TestPinnedConsumptionHoldsCustodyAndWipesAfterCallbackPanic(t *testing.T) {
	s := fixtureStore(t)
	human := fixtureContext("selected", true)
	agent := fixtureContext("selected", false)
	target := fixtureBinding().Target
	ref, err := s.Create(human, target, []byte("fixture-user"), []byte("fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := s.Metadata(human, target)
	if err != nil {
		t.Fatal(err)
	}
	var retained Credentials
	err = s.ConsumeRevision(agent, target, ref, meta.Revision, func(c Credentials) error {
		retained = c
		if _, e := s.Update(human, target, meta.Revision, []byte("new-user"), []byte("new-password")); !errors.Is(e, ErrBusy) {
			t.Fatal("selection changed during private consumption")
		}
		panic("PRIVATE-CANARY")
	})
	if err != ErrUnavailable {
		t.Fatal("private panic escaped")
	}
	if !bytes.Equal(retained.username, make([]byte, len(retained.username))) || !bytes.Equal(retained.password, make([]byte, len(retained.password))) {
		t.Fatal("callback buffers survived")
	}
	if _, err = s.Update(human, target, meta.Revision, []byte("new-user"), []byte("new-password")); err != nil {
		t.Fatal("custody not released after panic")
	}
}

func TestPinnedConsumptionRejectsForeignReferenceMalformedRevisionAndCancellation(t *testing.T) {
	s := fixtureStore(t)
	human := fixtureContext("selected", true)
	agent := fixtureContext("selected", false)
	target := fixtureBinding().Target
	ref, err := s.Create(human, target, []byte("fixture-user"), []byte("fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := s.Metadata(human, target)
	if err != nil {
		t.Fatal(err)
	}
	deny := func(Credentials) error { t.Fatal("invalid selection consumed"); return nil }
	for _, revision := range []string{"", strings.Repeat("z", 64), strings.Repeat("0", 64)} {
		if err = s.ConsumeRevision(agent, target, ref, revision, deny); err == nil {
			t.Fatal("bad revision accepted")
		}
	}
	if err = s.ConsumeRevision(fixtureContext("foreign", false), target, ref, meta.Revision, deny); err == nil {
		t.Fatal("foreign reference accepted")
	}
	ctx, cancel := context.WithCancel(agent)
	cancel()
	if err = s.ConsumeRevision(ctx, target, ref, meta.Revision, deny); err == nil {
		t.Fatal("cancelled delivery accepted")
	}
}

func TestPinnedManagerChecksFreshDocumentBeforeConsumption(t *testing.T) {
	s := fixtureStore(t)
	ctx := fixtureContext("selected", true)
	b := fixtureBinding()
	ref, err := s.Create(ctx, b.Target, []byte("fixture-user"), []byte("fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := s.Metadata(ctx, b.Target)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(s, Hooks{Present: func(context.Context, Request) error { return nil }, Resume: func(context.Context, Binding, Reference) error { return nil }, Fresh: func(context.Context, Binding) (Binding, error) {
		changed := b
		changed.DocumentID = "changed"
		return changed, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.ConsumeRevision(ctx, b, ref, meta.Revision, func(Credentials) error { t.Fatal("stale document consumed secret"); return nil }); err != ErrStale {
		t.Fatal("document check omitted")
	}
}
