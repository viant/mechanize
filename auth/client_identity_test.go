package auth

import (
	"context"
	"encoding/base64"
	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifiedClientEnrollment(t *testing.T) {
	key := []byte("fixture-consent-client-key-32-bytes-long")
	path := filepath.Join(t.TempDir(), "key")
	if e := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0600); e != nil {
		t.Fatal(e)
	}
	clients := map[string]string{"agent": "Enrolled Agent"}
	v, e := NewVerifier(context.Background(), &verifier.Config{HMAC: &scy.Resource{URL: path}}, Policy{Issuer: "fixture", Audience: "mechanize", Algorithms: []string{"HS256"}, Clients: clients})
	if e != nil {
		t.Fatal(e)
	}
	clients["agent"] = "Changed externally"
	for _, tc := range []struct {
		id    any
		key   []byte
		valid bool
	}{{"agent", key, true}, {"unknown", key, false}, {nil, key, false}, {42, key, false}, {"agent", []byte("forged-key"), false}} {
		c := jwt.MapClaims{"iss": "fixture", "sub": "human", "aud": "mechanize", "exp": time.Now().Add(time.Hour).Unix(), "client_id": tc.id, "client_name": "Forged Display"}
		raw, e := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(tc.key)
		if e != nil {
			t.Fatal(e)
		}
		p, e := v.Verify(context.Background(), raw)
		if (e == nil) != tc.valid {
			t.Fatalf("id=%v valid=%v err=%v", tc.id, tc.valid, e)
		}
		if tc.valid && (p.ClientID != "agent" || p.ClientName != "Enrolled Agent") {
			t.Fatalf("untrusted display identity: %+v", p)
		}
	}
}
func TestHumanTransportAssertion(t *testing.T) {
	p, _ := NewPrincipal("fixture", "", "human", []string{"consent:admin"})
	ctx := WithPrincipal(context.Background(), p)
	if NativeHuman(ctx) {
		t.Fatal("scope alone became native human")
	}
	ctx, e := WithNativeHuman(ctx)
	if e != nil || !NativeHuman(ctx) {
		t.Fatalf("trusted assertion failed: %v", e)
	}
	other, _ := NewPrincipal("fixture", "", "different-human", []string{"consent:admin"})
	if NativeHuman(WithPrincipal(ctx, other)) {
		t.Fatal("transport assertion transferred across principal")
	}
}
