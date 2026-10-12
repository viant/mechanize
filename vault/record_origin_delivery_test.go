package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/scy/kms"
)

func originDeliveryFixture(t *testing.T) (*RecordStore, context.Context, context.Context, Binding) {
	t.Helper()
	r := fixtureRecordStore(t)
	p, _ := auth.NewPrincipal("fixture", "", "origin-delivery", []string{"desktop:control", "consent:admin"})
	p.ClientID = "automation"
	ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "login"})
	human, _ := auth.WithNativeHuman(ctx)
	return r, ctx, human, Binding{SessionID: "session", DocumentID: "document", NavigationID: strings.Repeat("a", 64), Target: Target{Origin: "https://fixture.invalid", Account: "opaque"}}
}
func originRecordValues(t *testing.T, key, endpoint string, typed bool) RecordValues {
	t.Helper()
	fields := [][2][]byte{{[]byte("username"), []byte("username-canary")}, {[]byte("password"), []byte("password-canary")}}
	if endpoint != "" {
		fields = append(fields, [2][]byte{[]byte("endpoint"), []byte(endpoint)})
	}
	if typed {
		fields = append(fields, [2][]byte{[]byte(scyTypeField), []byte("basic")})
	}
	v, e := NewRecordValues([]byte(key), fields)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestOriginRecordDeliveryExactUniqueBasicAndNoProjection(t *testing.T) {
	for _, endpoint := range []string{"https://fixture.invalid", "https://fixture.invalid/"} {
		t.Run(endpoint, func(t *testing.T) {
			r, ctx, human, b := originDeliveryFixture(t)
			meta, e := r.Create(human, originRecordValues(t, "private-record-name", endpoint, true))
			if e != nil {
				t.Fatal(e)
			}
			authorized := true
			guard := func(context.Context) error {
				if !authorized {
					return auth.ErrUnauthorized
				}
				return nil
			}
			d, revision, e := ResolveOriginRecordDelivery(ctx, r, b.Target, time.Now().Add(time.Minute), guard)
			if e != nil || d == nil || revision != meta.Revision || d.Verify(ctx, b) != nil {
				t.Fatal("eligible record unavailable", e)
			}
			for _, v := range []any{d, *d} {
				raw, e := json.Marshal(v)
				if e == nil || strings.Contains(string(raw), "canary") || strings.Contains(fmt.Sprintf("%#v", v), "private-record-name") {
					t.Fatal("private capability projected")
				}
			}
			manager, e := NewRecordDeliveryManager(d, func(_ context.Context, actual Binding) (Binding, error) { return actual, nil })
			if e != nil {
				t.Fatal(e)
			}
			calls := 0
			var retained []byte
			consume := func(ref Reference, revision string) error {
				return manager.ConsumeRevision(ctx, b, ref, revision, func(c Credentials) error {
					return c.WithBytes(func(u, p []byte) error {
						calls++
						retained = u
						if string(u) != "username-canary" || string(p) != "password-canary" {
							t.Fatal("credential changed")
						}
						return nil
					})
				})
			}
			if e = d.UseBinding(ctx, b, consume); e != nil || calls != 1 {
				t.Fatal("private consumption", e)
			}
			for _, v := range retained {
				if v != 0 {
					t.Fatal("plaintext not wiped")
				}
			}
			authorized = false
			if next, _, err := ResolveOriginRecordDelivery(ctx, r, b.Target, time.Now().Add(time.Minute), guard); err == nil || next != nil {
				t.Fatal("revoked consent admitted new resolution")
			}
			authorized = true
			if _, e = r.Update(human, meta.Reference, meta.Revision, originRecordValues(t, "private-record-name", endpoint, true)); e != nil {
				t.Fatal(e)
			}
			if e = d.UseBinding(ctx, b, consume); e == nil || calls != 1 {
				t.Fatal("changed record revision consumed")
			}
			d.Revoke()
			if d.Verify(ctx, b) == nil {
				t.Fatal("revoked capability reused")
			}
		})
	}
}
func TestOriginRecordDeliveryNeverWidensEndpointOrAccountSelection(t *testing.T) {
	for _, endpoint := range []string{"", "http://fixture.invalid", "https://other.invalid", "https://fixture.invalid/path", "https://fixture.invalid//", "https://fixture.invalid/?x=1", "https://fixture.invalid#fragment", "https://user@fixture.invalid", "https://fixture.invalid:443", "https://FIXTURE.invalid", "https://fixture.invalid?", "https://fixture.invalid/%2F"} {
		t.Run(endpoint, func(t *testing.T) {
			r, ctx, human, b := originDeliveryFixture(t)
			if _, e := r.Create(human, originRecordValues(t, "name", endpoint, true)); e != nil {
				t.Fatal(e)
			}
			d, rev, e := ResolveOriginRecordDelivery(ctx, r, b.Target, time.Now().Add(time.Minute), func(context.Context) error { return nil })
			if d != nil || rev != "" || !errors.Is(e, ErrCredentialConfiguration) {
				t.Fatal("ineligible endpoint admitted", e)
			}
		})
	}
	for _, mode := range []string{"legacy", "ambiguous", "foreignNamespace"} {
		t.Run(mode, func(t *testing.T) {
			r, ctx, human, b := originDeliveryFixture(t)
			admin := human
			if mode == "foreignNamespace" {
				p, _ := auth.NewPrincipal("fixture", "", "foreign", []string{"consent:admin"})
				admin, _ = auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
			}
			if _, e := r.Create(admin, originRecordValues(t, "first", b.Target.Origin, mode != "legacy")); e != nil {
				t.Fatal(e)
			}
			if mode == "ambiguous" {
				if _, e := r.Create(admin, originRecordValues(t, "second", b.Target.Origin, true)); e != nil {
					t.Fatal(e)
				}
			}
			d, rev, e := ResolveOriginRecordDelivery(ctx, r, b.Target, time.Now().Add(time.Minute), func(context.Context) error { return nil })
			if d != nil || rev != "" || !errors.Is(e, ErrCredentialConfiguration) {
				t.Fatal("ambiguous/foreign/legacy selection admitted", e)
			}
		})
	}
}
func TestOriginRecordDeliveryRequiresRealControlConsentAndActor(t *testing.T) {
	r, ctx, human, b := originDeliveryFixture(t)
	if _, e := r.Create(human, originRecordValues(t, "name", b.Target.Origin, true)); e != nil {
		t.Fatal(e)
	}
	p, _ := auth.FromContext(ctx)
	observe := p
	observe.Scopes = []string{"desktop:observe"}
	noClient := p
	noClient.ClientID = ""
	for _, c := range []context.Context{human, context.Background(), auth.WithPrincipal(ctx, observe), auth.WithPrincipal(ctx, noClient), auth.WithPrincipal(context.Background(), p)} {
		if d, _, e := ResolveOriginRecordDelivery(c, r, b.Target, time.Now().Add(time.Minute), func(context.Context) error { return nil }); e == nil || d != nil {
			t.Fatal("missing control actor/consent accepted")
		}
	}
	for _, guard := range []func(context.Context) error{nil, func(context.Context) error { return auth.ErrUnauthorized }} {
		if d, _, e := ResolveOriginRecordDelivery(ctx, r, b.Target, time.Now().Add(time.Minute), guard); e == nil || d != nil {
			t.Fatal("unverified consent accepted")
		}
	}
	d, _, e := ResolveOriginRecordDelivery(ctx, r, b.Target, time.Now().Add(time.Minute), func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	foreign := p
	foreign.ClientID = "other"
	if d.Verify(auth.WithPrincipal(ctx, foreign), b) == nil {
		t.Fatal("foreign client reused delivery")
	}
	other, _ := auth.NewPrincipal("fixture", "", "other", []string{"desktop:control"})
	other.ClientID = p.ClientID
	if d.Verify(auth.WithPrincipal(ctx, other), b) == nil {
		t.Fatal("foreign namespace reused delivery")
	}
	changed := b
	changed.Target.Origin = "https://other.invalid"
	if d.Verify(ctx, changed) == nil {
		t.Fatal("cross origin delivery")
	}
}

// Retain aliases only in the synthetic cipher to prove the production resolver
// erases every owned decrypted buffer, including ambiguous/configuration paths.
type originTrackingCipher struct {
	*Cipher
	plains [][]byte
}

func (c *originTrackingCipher) Decrypt(ctx context.Context, key *kms.Key, encrypted []byte) ([]byte, error) {
	plain, err := c.Cipher.Decrypt(ctx, key, encrypted)
	c.plains = append(c.plains, plain)
	return plain, err
}
func TestOriginRecordResolutionWipesEveryBufferAndChecksConsentBeforeDecrypt(t *testing.T) {
	for _, mode := range []string{"unique", "missing", "ambiguous", "revoked", "revokedDuringResolve"} {
		t.Run(mode, func(t *testing.T) {
			r, ctx, human, b := originDeliveryFixture(t)
			endpoint := b.Target.Origin
			if mode == "missing" {
				endpoint = "https://other.invalid"
			}
			if _, err := r.Create(human, originRecordValues(t, "first", endpoint, true)); err != nil {
				t.Fatal(err)
			}
			if mode == "ambiguous" {
				if _, err := r.Create(human, originRecordValues(t, "second", endpoint, true)); err != nil {
					t.Fatal(err)
				}
			}
			tracking := &originTrackingCipher{Cipher: r.store.cipher.(*Cipher)}
			r.store.cipher = tracking
			checks := 0
			guard := func(context.Context) error {
				checks++
				if mode == "revoked" || mode == "revokedDuringResolve" && checks > 1 {
					return auth.ErrUnauthorized
				}
				return nil
			}
			d, _, err := ResolveOriginRecordDelivery(ctx, r, b.Target, time.Now().Add(time.Minute), guard)
			if (mode == "unique") != (err == nil && d != nil) {
				t.Fatal("resolution result", err)
			}
			if mode == "revoked" && len(tracking.plains) != 0 {
				t.Fatal("decrypted before actual consent")
			}
			if mode == "revokedDuringResolve" && !errors.Is(err, auth.ErrUnauthorized) {
				t.Fatal("revocation during scan became configuration success", err)
			}
			if mode != "revoked" && len(tracking.plains) == 0 {
				t.Fatal("fixture never exercised decryption")
			}
			for _, plain := range tracking.plains {
				for _, value := range plain {
					if value != 0 {
						t.Fatal("decrypted record bytes survived resolution")
					}
				}
			}
		})
	}
}
