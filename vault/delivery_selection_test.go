package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

func selectionFixture(t *testing.T) (*Store, context.Context, context.Context, Binding, EntryMetadata, *DeliverySelection, *atomic.Bool) {
	t.Helper()
	store := fixtureStore(t)
	actor, _ := auth.NewPrincipal("fixture", "", "selection-owner", []string{"desktop:control"})
	actor.ClientID = "automation-client"
	automation := auth.WithPrincipal(context.Background(), actor)
	automation = auth.WithConsentBinding(automation, auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "private login"})
	native, _ := auth.NewPrincipal("fixture", "", "selection-owner", []string{"consent:admin"})
	native.ClientID = "native-console"
	human, e := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), native))
	if e != nil {
		t.Fatal(e)
	}
	binding := Binding{SessionID: "session", DocumentID: "document", NavigationID: strings.Repeat("a", 64), Target: Target{Origin: "https://private-origin.invalid", Account: "private-account"}}
	if _, e = store.Create(human, binding.Target, []byte("username-secret-canary"), []byte("password-secret-canary")); e != nil {
		t.Fatal(e)
	}
	metadata, e := store.Metadata(human, binding.Target)
	if e != nil {
		t.Fatal(e)
	}
	allowed := &atomic.Bool{}
	allowed.Store(true)
	selection, e := NewDeliverySelection(human, automation, store, binding, metadata, time.Now().Add(time.Minute), func(ctx context.Context) error {
		actual, e := auth.FromContext(ctx)
		if e != nil || actual.ClientID != "automation-client" || !allowed.Load() {
			return errors.New("guard-private-canary")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return store, human, automation, binding, metadata, selection, allowed
}
func recipientFor(b Binding) DeliveryRecipient {
	return DeliveryRecipient{b.SessionID, b.DocumentID, b.NavigationID, b.Target.Origin}
}
func TestDeliverySelectionPrivateAndRevisionPinned(t *testing.T) {
	store, human, ctx, binding, metadata, selection, _ := selectionFixture(t)
	for _, v := range []any{selection, *selection} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			text := fmt.Sprintf(format, v)
			for _, private := range []string{binding.Target.Origin, binding.Target.Account, metadata.Reference.ResourceURL, metadata.Revision, "canary"} {
				if strings.Contains(text, private) {
					t.Fatal("selection formatting disclosed routing")
				}
			}
		}
		if raw, e := json.Marshal(v); e == nil || strings.Contains(string(raw), "private") {
			t.Fatal("selection serialized")
		}
	}
	calls := 0
	for i := 0; i < 2; i++ {
		if e := selection.UseBinding(ctx, recipientFor(binding), func(actual Binding, ref Reference, revision string) error {
			calls++
			if actual != binding || ref != metadata.Reference || revision != metadata.Revision {
				t.Fatal("selection metadata changed")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	if calls != 2 {
		t.Fatal("authorized same-session reuse unavailable")
	}
	err := selection.UseBinding(ctx, recipientFor(binding), func(actual Binding, ref Reference, revision string) error {
		if _, e := store.Update(human, actual.Target, revision, []byte("changed-user"), []byte("changed-password")); e != nil {
			t.Fatal(e)
		}
		return store.ConsumeRevision(ctx, actual.Target, ref, revision, func(Credentials) error { t.Fatal("changed ciphertext consumed under old selection"); return nil })
	})
	if err == nil {
		t.Fatal("revision drift accepted")
	}
	if e := selection.UseBinding(ctx, recipientFor(binding), func(Binding, Reference, string) error { t.Fatal("stale selected metadata reused"); return nil }); e == nil {
		t.Fatal("stale selection accepted")
	}
}
func TestDeliverySelectionFactoryRequiresActualNativeAndOriginalConsent(t *testing.T) {
	store, human, ctx, binding, metadata, _, _ := selectionFixture(t)
	native, _ := auth.FromContext(human)
	for _, kind := range []string{"noNative", "foreignNamespace", "noControl", "wrongSession", "missingGrant", "missingPurpose", "past", "tooLong", "ref", "revision", "noGuard", "guardPanic"} {
		t.Run(kind, func(t *testing.T) {
			h, a, b, m := human, ctx, binding, metadata
			expires := time.Now().Add(time.Minute)
			guard := func(context.Context) error { return nil }
			switch kind {
			case "noNative":
				h = auth.WithPrincipal(context.Background(), native)
			case "foreignNamespace":
				other, _ := auth.NewPrincipal("fixture", "", "other", []string{"desktop:control"})
				other.ClientID = "automation-client"
				a = auth.WithPrincipal(a, other)
			case "noControl":
				a = auth.WithPrincipal(a, native)
			case "wrongSession":
				b.SessionID = "other"
			case "missingGrant":
				a = auth.WithConsentBinding(a, auth.ConsentBinding{SessionID: b.SessionID, Purpose: "private login"})
			case "missingPurpose":
				a = auth.WithConsentBinding(a, auth.ConsentBinding{SessionID: b.SessionID, GrantID: "grant"})
			case "past":
				expires = time.Now().Add(-time.Second)
			case "tooLong":
				expires = time.Now().Add(6 * time.Minute)
			case "ref":
				m.Reference.ResourceURL = "mechanize-vault://other"
			case "revision":
				m.Revision = strings.Repeat("f", 64)
			case "noGuard":
				guard = nil
			case "guardPanic":
				guard = func(context.Context) error { panic("private-secret-canary") }
			}
			selected, e := NewDeliverySelection(h, a, store, b, m, expires, guard)
			if e == nil || selected != nil || strings.Contains(fmt.Sprint(e), "canary") {
				t.Fatal("unsafe factory admission")
			}
		})
	}
}
func TestDeliverySelectionRefusesChangedRecipientActorAndRevocation(t *testing.T) {
	store, human, ctx, b, metadata, s, allowed := selectionFixture(t)
	for _, kind := range []string{"client", "namespace", "session", "grant", "purpose", "document", "navigation", "origin", "cancelled", "denied"} {
		t.Run(kind, func(t *testing.T) {
			changed := ctx
			recipient := recipientFor(b)
			switch kind {
			case "client":
				p, _ := auth.FromContext(ctx)
				p.ClientID = "other"
				changed = auth.WithPrincipal(ctx, p)
			case "namespace":
				p, _ := auth.NewPrincipal("fixture", "", "other", []string{"desktop:control"})
				p.ClientID = "automation-client"
				changed = auth.WithPrincipal(ctx, p)
			case "session", "grant", "purpose":
				c, _ := auth.ConsentBindingFromContext(ctx)
				if kind == "session" {
					c.SessionID = "other"
				}
				if kind == "grant" {
					c.GrantID = "other"
				}
				if kind == "purpose" {
					c.Purpose = "other"
				}
				changed = auth.WithConsentBinding(ctx, c)
			case "document":
				recipient.DocumentID = "other"
			case "navigation":
				recipient.NavigationID = strings.Repeat("f", 64)
			case "origin":
				recipient.Origin = "https://other.invalid"
			case "cancelled":
				var cancel context.CancelFunc
				changed, cancel = context.WithCancel(ctx)
				cancel()
			case "denied":
				allowed.Store(false)
				defer allowed.Store(true)
			}
			if e := s.UseBinding(changed, recipient, func(Binding, Reference, string) error { t.Fatal("unauthorized callback ran"); return nil }); e == nil || strings.Contains(fmt.Sprint(e), "canary") {
				t.Fatal("unsafe use admitted")
			}
		})
	}
	s.Revoke()
	if e := s.UseBinding(ctx, recipientFor(b), func(Binding, Reference, string) error { t.Fatal("revoked callback ran"); return nil }); e == nil {
		t.Fatal("revocation ignored")
	}
	if actual, e := store.Metadata(human, b.Target); e != nil || actual != metadata {
		t.Fatal("selection refusal modified credential metadata")
	}
}
func TestDeliverySelectionConcurrentUseExpiryAndCallbackPanic(t *testing.T) {
	_, _, ctx, b, _, s, _ := selectionFixture(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- s.UseBinding(ctx, recipientFor(b), func(Binding, Reference, string) error { close(entered); <-release; return nil })
	}()
	<-entered
	if e := s.UseBinding(ctx, recipientFor(b), func(Binding, Reference, string) error { t.Fatal("concurrent use ran"); return nil }); e == nil {
		t.Fatal("concurrent use admitted")
	}
	s.Revoke()
	close(release)
	if e := <-done; e == nil {
		t.Fatal("revocation during use returned success")
	}
	_, _, ctx, b, _, s, _ = selectionFixture(t)
	if e := s.UseBinding(ctx, recipientFor(b), func(Binding, Reference, string) error { panic("private-secret-canary") }); e == nil || strings.Contains(fmt.Sprint(e), "canary") {
		t.Fatal("callback panic leaked")
	}
	s.state.mu.Lock()
	s.state.expires = time.Now().Add(-time.Second)
	s.state.mu.Unlock()
	if e := s.UseBinding(ctx, recipientFor(b), func(Binding, Reference, string) error { t.Fatal("expired callback ran"); return nil }); e == nil {
		t.Fatal("expiry ignored")
	}
}

func TestDeliverySelectionVerifyInsideCustodyRefusesRevocationBeforeWrite(t *testing.T) {
	store, _, ctx, binding, _, selection, _ := selectionFixture(t)
	recipient := recipientFor(binding)
	writes := 0
	err := selection.UseBinding(ctx, recipient, func(actual Binding, ref Reference, revision string) error {
		// The production Gateway guard runs here, inside Store.ConsumeRevision's
		// custody lock. Verify must not recurse through authorization or Metadata.
		return store.ConsumeRevision(ctx, actual.Target, ref, revision, func(Credentials) error {
			originalGuard := selection.state.authorize
			selection.state.authorize = func(context.Context) error {
				t.Fatal("Verify recursed through host authorization")
				return ErrUnavailable
			}
			defer func() { selection.state.authorize = originalGuard }()
			if e := selection.Verify(ctx, recipient); e != nil {
				t.Fatal("active selection failed metadata verification", e)
			}
			selection.Revoke()
			if e := selection.Verify(ctx, recipient); e != nil {
				return e
			}
			writes++
			return nil
		})
	})
	if err == nil || writes != 0 {
		t.Fatal("revoked selection reached private credential write")
	}
	if e := selection.Verify(ctx, recipient); e == nil {
		t.Fatal("revoked metadata guard became reusable")
	}
}

func TestDeliverySelectionVerifyRefusesExpiredOrChangedBinding(t *testing.T) {
	_, _, ctx, binding, _, selection, _ := selectionFixture(t)
	recipient := recipientFor(binding)
	bad := recipient
	bad.NavigationID = strings.Repeat("f", 64)
	if selection.Verify(ctx, bad) == nil {
		t.Fatal("changed recipient verified")
	}
	p, _ := auth.FromContext(ctx)
	p.ClientID = "other"
	if selection.Verify(auth.WithPrincipal(ctx, p), recipient) == nil {
		t.Fatal("foreign client verified")
	}
	consent, _ := auth.ConsentBindingFromContext(ctx)
	consent.GrantID = "other"
	if selection.Verify(auth.WithConsentBinding(ctx, consent), recipient) == nil {
		t.Fatal("foreign grant verified")
	}
	selection.state.mu.Lock()
	selection.state.expires = time.Now().Add(-time.Second)
	selection.state.mu.Unlock()
	if selection.Verify(ctx, recipient) == nil {
		t.Fatal("expired selection verified")
	}
}
