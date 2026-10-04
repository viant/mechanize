package auth

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
)

func TestScyVerificationAndIdentityIsolation(t *testing.T) {
	key := []byte("fixture-only-randomish-32-byte-key-123456789")
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(context.Background(), &verifier.Config{HMAC: &scy.Resource{URL: path}}, Policy{Issuer: "https://issuer.example", Audience: "mechanize", Algorithms: []string{"HS256"}, RequiredScopes: []string{"desktop:read"}})
	if err != nil {
		t.Fatal(err)
	}
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"iss": "https://issuer.example", "sub": "employee-1", "aud": "mechanize", "exp": time.Now().Add(time.Hour).Unix(), "scope": "desktop:read"}
	}
	cases := []struct {
		name  string
		alter func(jwt.MapClaims)
		valid bool
	}{
		{"valid", func(jwt.MapClaims) {}, true},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = "another-resource" }, false},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "https://other.example" }, false},
		{"missing expiry", func(c jwt.MapClaims) { delete(c, "exp") }, false},
		{"missing subject", func(c jwt.MapClaims) { delete(c, "sub") }, false},
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, false},
		{"missing scope", func(c jwt.MapClaims) { delete(c, "scope") }, false},
		{"future not before", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, false},
	}
	var namespaceKey string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := base()
			tc.alter(claims)
			raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			p, err := v.Verify(context.Background(), raw)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if tc.valid {
				namespaceKey = p.Namespace
				claims["exp"] = time.Now().Add(2 * time.Hour).Unix()
				refreshed, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
				other, err := v.Verify(context.Background(), refreshed)
				if err != nil || other.Namespace != p.Namespace {
					t.Fatal("token refresh changed identity")
				}
			}
		})
	}
	other, _ := NewPrincipal("https://another-issuer.example", "", "employee-1", nil)
	if namespaceKey == other.Namespace {
		t.Fatal("issuer collision")
	}
	if _, err := (NamespaceProvider{}).Namespace(context.Background()); err == nil {
		t.Fatal("anonymous namespace admitted")
	}
	forged, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, base()).SignedString([]byte("wrong-key"))
	if _, err := v.Verify(context.Background(), forged); err == nil {
		t.Fatal("forged signature admitted")
	}
}
