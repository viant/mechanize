package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/internal/devcredential"
	"github.com/viant/scy"
	scyjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/auth/jwt/signer"
	"github.com/viant/scy/auth/jwt/verifier"
)

func developmentCredentialFixture(t *testing.T, remaining time.Duration) (string, string, *auth.Verifier) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	configDir, credentialDir := filepath.Join(root, "current"), filepath.Join(root, "retained", "credentials")
	for _, dir := range []string{configDir, credentialDir} {
		if err = os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	key := []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{47}, 32)))
	keyPath, tokenPath := filepath.Join(credentialDir, "hmac"), filepath.Join(credentialDir, "stdio.jwt")
	if err = os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	policy := auth.Policy{Issuer: fmt.Sprintf("mechanize:development:%d", os.Getuid()), Audience: "mechanize-development", Algorithms: []string{"HS256"}, Clients: map[string]string{"development-agent": "Local developer"}}
	keys := verifier.Config{HMAC: &scy.Resource{URL: keyPath, Data: key}}
	s := signer.New(&signer.Config{Rules: []*signer.Rule{{Resource: []string{policy.Audience}, Algorithm: "HS256", HMAC: keys.HMAC}}})
	if err = s.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	claims := &scyjwt.Claims{Scope: "desktop:observe desktop:control", RegisteredClaims: jwt.RegisteredClaims{Issuer: policy.Issuer, Subject: fmt.Sprintf("local-uid-%d", os.Getuid()), Audience: jwt.ClaimStrings{policy.Audience}}}
	old, err := s.Create(devcredential.Lifetime, claims, func(token *jwt.Token) {
		b, _ := json.Marshal(token.Claims)
		var m jwt.MapClaims
		_ = json.Unmarshal(b, &m)
		m["client_id"] = "development-agent"
		m["iat"] = time.Now().Add(-2 * time.Hour).Unix()
		m["nbf"] = time.Now().Add(-2 * time.Hour).Unix()
		m["exp"] = time.Now().Add(remaining).Unix()
		token.Claims = m
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(tokenPath, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	configuration := map[string]any{"keys": verifier.Config{HMAC: &scy.Resource{URL: keyPath}}, "identityPolicy": policy, "stdioCredential": &scy.Resource{URL: tokenPath}, "users": []map[string]string{{"subject": claims.Subject}}}
	b, _ := json.Marshal(configuration)
	path := filepath.Join(configDir, "config.json")
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	v, err := auth.NewVerifier(context.Background(), &keys, policy)
	if err != nil {
		t.Fatal(err)
	}
	return path, old, v
}
func TestSecureTransportRenewsLocalCredentialBeforeOneDispatch(t *testing.T) {
	for _, remaining := range []time.Duration{30 * time.Minute, -time.Hour} {
		for _, status := range []int{http.StatusOK, http.StatusUnauthorized} {
			t.Run(fmt.Sprintf("remaining=%s/status=%d", remaining, status), func(t *testing.T) {
				path, old, v := developmentCredentialFixture(t, remaining)
				target := "http://127.0.0.1:4987/mcp"
				calls := 0
				transport := &secureTransport{endpoint: target, loadCredential: func(ctx context.Context) (string, error) { return credential(ctx, path) }, base: credentialRoundTrip(func(r *http.Request) (*http.Response, error) {
					calls++
					raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
					p, err := v.Verify(r.Context(), raw)
					if err != nil || raw == old || p.ClientID != "development-agent" || len(p.Scopes) != 2 || p.HasScope("consent:admin") {
						t.Fatal("transport did not use a verified renewed fixed identity")
					}
					return credentialResponse(status), nil
				})}
				request := credentialRequest(t, target)
				request.Header.Set("Authorization", "caller-owned-header")
				response, err := transport.RoundTrip(request)
				if status == http.StatusOK {
					if err != nil {
						t.Fatal("renewed request failed")
					}
					response.Body.Close()
				} else if !errors.Is(err, errMCPAuthDenied) {
					t.Fatal("authentication failure lost its safe category")
				}
				if calls != 1 || request.Header.Get("Authorization") != "caller-owned-header" {
					t.Fatal("operation was replayed or caller headers changed")
				}
			})
		}
	}
}
