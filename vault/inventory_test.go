package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"os"
	"strings"
	"testing"

	"github.com/viant/scy/kms"
)

type inventorySpyCipher struct {
	*Cipher
	decryptions int
}

func (c *inventorySpyCipher) Decrypt(ctx context.Context, key *kms.Key, b []byte) ([]byte, error) {
	c.decryptions++
	return c.Cipher.Decrypt(ctx, key, b)
}
func TestNativeInventoryReturnsRoutingAndRevisionWithoutCredentialValues(t *testing.T) {
	s := fixtureStore(t)
	ctx := fixtureContext("inventory-owner", true)
	target := fixtureBinding().Target
	if _, err := s.Create(ctx, target, []byte("synthetic-username-canary"), []byte("synthetic-password-canary")); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Inventory(ctx)
	if err != nil || len(rows) != 1 || rows[0].Origin != target.Origin || rows[0].AccountAlias != target.Account || !nativeRevision(rows[0].Revision) {
		t.Fatal("native inventory failed")
	}
	encoded, _ := json.Marshal(rows)
	if bytes.Contains(encoded, []byte("canary")) || strings.Contains(string(encoded), "username") || strings.Contains(string(encoded), "password") {
		t.Fatal("credential data escaped inventory")
	}
	if _, err = s.Inventory(fixtureContext("inventory-owner", false)); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("agent enumerated native Vault")
	}
	if err = s.Delete(ctx, target, rows[0].Revision); err != nil {
		t.Fatal(err)
	}
	rows, err = s.Inventory(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatal("deleted entry remained in inventory")
	}
}
func TestNativeInventoryVerifiesRoutingWithoutDecryptingForeignNamespace(t *testing.T) {
	s := fixtureStore(t)
	foreign := fixtureContext("foreign-owner", true)
	target := fixtureBinding().Target
	if _, err := s.Create(foreign, target, []byte("foreign-user-canary"), []byte("foreign-password-canary")); err != nil {
		t.Fatal(err)
	}
	spy := &inventorySpyCipher{Cipher: s.cipher.(*Cipher)}
	s.cipher = spy
	rows, err := s.Inventory(fixtureContext("inventory-owner", true))
	if err != nil || len(rows) != 0 || spy.decryptions != 0 {
		t.Fatal("foreign credentials were decrypted/enumerated")
	}
}
func TestNativeInventoryTamperedRoutingRefusesRatherThanReportingEmpty(t *testing.T) {
	s := fixtureStore(t)
	ctx := fixtureContext("inventory-owner", true)
	target := fixtureBinding().Target
	if _, err := s.Create(ctx, target, []byte("user"), []byte("password")); err != nil {
		t.Fatal(err)
	}
	_, id, _ := scoped(ctx, target)
	name := id + ".enc"
	f, _ := s.root.Open(name)
	var e envelope
	json.NewDecoder(f).Decode(&e)
	f.Close()
	e.Namespace = strings.Repeat("a", 64)
	data, _ := json.Marshal(e)
	f, err := s.root.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(data)
	f.Close()
	if rows, err := s.Inventory(ctx); !errors.Is(err, ErrUnavailable) || rows != nil {
		t.Fatal("tampered namespace was hidden as an empty Vault")
	}
}
