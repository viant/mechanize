package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/scy/auth/jwt/verifier"
)

func TestRemoteVerificationErrorsAndWarmKeyReuse(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	var unavailable atomic.Bool
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if unavailable.Load() {
			http.Error(w, "dependency unavailable", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "fixture", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer keys.Close()
	policy := Policy{Issuer: "https://issuer.example", Audience: "browser", Algorithms: []string{"RS256"}, RequiredScopes: []string{"browser:use"}, Clients: map[string]string{"fixture": "Fixture"}}
	newVerifier := func() *Verifier {
		t.Helper()
		v, err := NewVerifier(context.Background(), &verifier.Config{CertURL: keys.URL}, policy)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	sign := func(exp int64) string {
		t.Helper()
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": policy.Issuer, "aud": policy.Audience, "exp": exp, "sub": "user", "scope": "browser:use", "client_id": "fixture"})
		token.Header["kid"] = "fixture"
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	raw := sign(time.Now().Add(time.Hour).Unix())
	status := func(v *Verifier, ctx context.Context, token string) int {
		t.Helper()
		r := httptest.NewRequest("POST", "http://service.example/mcp", nil).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
		return w.Code
	}
	v := newVerifier()
	for i := 0; i < 5; i++ {
		if got := status(v, context.Background(), raw); got != 204 {
			t.Fatal(got)
		}
	}
	if got := status(v, context.Background(), sign(time.Now().Add(-time.Hour).Unix())); got != 401 {
		t.Fatal(got)
	}
	if requests.Load() != 1 {
		t.Fatalf("warm requests refetched keys: %d", requests.Load())
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.Verify(canceled, raw); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation identity lost: %v", err)
	}
	if got := status(v, canceled, raw); got != 408 {
		t.Fatal(got)
	}
	unavailable.Store(true)
	fresh := newVerifier()
	if _, err := fresh.Verify(context.Background(), raw); !errors.Is(err, ErrVerificationUnavailable) {
		t.Fatalf("dependency failure became authorization denial: %v", err)
	}
	if got := status(fresh, context.Background(), raw); got != 503 {
		t.Fatal(got)
	}
}
