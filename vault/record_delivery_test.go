package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/auth"
	"strings"
	"testing"
	"time"
)

func recordDeliveryFixture(t *testing.T) (*RecordStore, context.Context, context.Context, Binding, RecordMetadata, *RecordDelivery) {
	t.Helper()
	r := fixtureRecordStore(t)
	actor, _ := auth.NewPrincipal("fixture", "", "record-delivery", []string{"desktop:control"})
	actor.ClientID = "automation"
	ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), actor), auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "private login"})
	native, _ := auth.NewPrincipal("fixture", "", "record-delivery", []string{"consent:admin"})
	native.ClientID = "native"
	human, _ := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), native))
	v, _ := NewRecordValues([]byte("record-key-canary"), [][2][]byte{{[]byte("username"), []byte("username-canary")}, {[]byte("password"), []byte("password-canary")}, {[]byte("extra"), []byte("extra-canary")}})
	meta, e := r.Create(human, v)
	if e != nil {
		t.Fatal(e)
	}
	b := Binding{SessionID: "session", DocumentID: "document", NavigationID: strings.Repeat("a", 64), Target: Target{Origin: "https://fixture.invalid", Account: "opaque"}}
	d, e := ApproveRecordDelivery(human, ctx, r, b.Target, meta, time.Now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	return r, human, ctx, b, meta, d
}
func TestRecordDeliveryProductionConsumerRevisionBoundAndErases(t *testing.T) {
	r, human, ctx, b, meta, d := recordDeliveryFixture(t)
	m, e := NewRecordDeliveryManager(d, func(_ context.Context, actual Binding) (Binding, error) {
		if actual != b {
			t.Fatal("substituted binding")
		}
		return actual, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	var u, pw []byte
	calls := 0
	use := func(ref Reference, revision string) error {
		return m.ConsumeRevision(ctx, b, ref, revision, func(c Credentials) error {
			calls++
			return c.WithBytes(func(user, pass []byte) error {
				if string(user) != "username-canary" || string(pass) != "password-canary" {
					t.Fatal("wrong fields")
				}
				u = user
				pw = pass
				return nil
			})
		})
	}
	if e = d.UseBinding(ctx, b, use); e != nil || calls != 1 {
		t.Fatal(e, calls)
	}
	for _, v := range append(u, pw...) {
		if v != 0 {
			t.Fatal("plaintext not erased")
		}
	}
	v, _ := NewRecordValues([]byte("record-key-canary"), [][2][]byte{{[]byte("username"), []byte("changed")}, {[]byte("password"), []byte("changed")}})
	if _, e = r.Update(human, meta.Reference, meta.Revision, v); e != nil {
		t.Fatal(e)
	}
	if e = d.UseBinding(ctx, b, use); e == nil || calls != 1 {
		t.Fatal("selected ciphertext replaced")
	}
	if e = m.Consume(ctx, b, Reference{}, func(Credentials) error { t.Fatal("revisionless record consumption"); return nil }); e == nil {
		t.Fatal("record manager exposed mutable consumption")
	}
	if _, e = m.Ensure(ctx, b); e == nil {
		t.Fatal("record manager exposed mutable lookup")
	}
}
func TestRecordDeliveryNativeOnlyAndPrivateProjection(t *testing.T) {
	r, human, ctx, b, meta, d := recordDeliveryFixture(t)
	if _, e := ApproveRecordDelivery(ctx, ctx, r, b.Target, meta, time.Now().Add(time.Minute)); e == nil {
		t.Fatal("remote approval")
	}
	for _, v := range []any{d, *d} {
		if raw, e := json.Marshal(v); e == nil || strings.Contains(string(raw), "canary") {
			t.Fatal("serialized")
		}
		if strings.Contains(fmt.Sprintf("%+v", v), meta.Reference.ID) {
			t.Fatal("record reference leaked")
		}
	}
	altered := b
	altered.Target.Origin = "https://other.invalid"
	if d.Verify(ctx, altered) == nil {
		t.Fatal("origin changed")
	}
	actor, _ := auth.FromContext(ctx)
	actor.ClientID = "other"
	if d.Verify(auth.WithPrincipal(ctx, actor), b) == nil {
		t.Fatal("actor changed")
	}
	if d.Verify(human, b) == nil {
		t.Fatal("native authority substituted for automation")
	}
	d.Revoke()
	if d.Verify(ctx, b) == nil {
		t.Fatal("revoked capability admitted")
	}
}
func TestRecordDeliveryRejectsNonCredentialRecordAndBadRevision(t *testing.T) {
	r, human, ctx, b, meta, _ := recordDeliveryFixture(t)
	meta.Revision = strings.Repeat("f", 64)
	if _, e := ApproveRecordDelivery(human, ctx, r, b.Target, meta, time.Now().Add(time.Minute)); e == nil {
		t.Fatal("stale revision approved")
	}
	v, _ := NewRecordValues([]byte("noncredential"), [][2][]byte{{[]byte("token"), []byte("secret")}})
	meta, e := r.Create(human, v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ApproveRecordDelivery(human, ctx, r, b.Target, meta, time.Now().Add(time.Minute)); e == nil {
		t.Fatal("unmapped values consumed")
	}
}

func TestRecordDeliveryRefusesBinaryCredentialMappingBeforeProtection(t *testing.T) {
	r, human, ctx, b, _, _ := recordDeliveryFixture(t)
	for i, value := range [][]byte{{0xff}, {'a', 0, 'b'}} {
		values, e := NewRecordValues([]byte(fmt.Sprintf("synthetic-binary-record-%d", i)), [][2][]byte{{[]byte("username"), value}, {[]byte("password"), []byte("password-canary")}})
		if e != nil {
			t.Fatal(e)
		}
		metadata, e := r.Create(human, values)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = ApproveRecordDelivery(human, ctx, r, b.Target, metadata, time.Now().Add(time.Minute)); e == nil {
			t.Fatal("binary/native-only record entered browser credential delivery")
		}
	}
}

func TestExpiredSelectionRetainsOnlyPrivacyProvenance(t *testing.T) {
	_, _, ctx, b, _, d := recordDeliveryFixture(t)
	d.state.mu.Lock()
	d.state.expires = time.Now().Add(-time.Second)
	d.state.mu.Unlock()
	if d.Verify(ctx, b) == nil {
		t.Fatal("expired selection still permitted secret use")
	}
	if e := d.VerifyPrivacyBinding(ctx, b); e != nil {
		t.Fatal("retained metadata provenance unavailable", e)
	}
	if d.UseBinding(ctx, b, func(Reference, string) error { t.Fatal("expired selection entered consumer"); return nil }) == nil {
		t.Fatal("privacy verifier renewed credential consumption")
	}
	d.Revoke()
	if d.VerifyPrivacyBinding(ctx, b) == nil {
		t.Fatal("privacy check bypassed revocation")
	}
}
