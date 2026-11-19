package containerbrowser

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/mechanize/auth"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
)

func oauthFixture(t *testing.T) (*auth.Verifier, func(func(jwt.MapClaims)) string) {
	t.Helper()
	key := []byte("synthetic-browser-oauth-verification-key")
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := auth.NewVerifier(context.Background(), &verifier.Config{HMAC: &scy.Resource{URL: path}}, auth.Policy{
		Issuer: "https://issuer.example", Algorithms: []string{"HS256"},
		RequiredScopes: []string{"browser:use"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, func(alter func(jwt.MapClaims)) string {
		claims := jwt.MapClaims{"iss": "https://issuer.example", "aud": "https://browser.example/mcp", "sub": "user-a", "client_id": "client-a", "scope": "browser:use", "exp": time.Now().Add(time.Hour).Unix()}
		if alter != nil {
			alter(claims)
		}
		raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
}

func TestOAuthAuthenticationAndSessionOwnership(t *testing.T) {
	v, token := oauthFixture(t)
	raw := token(nil)
	p, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := ownerFromContext(auth.WithPrincipal(context.Background(), p))
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{Verifier: v, byTransport: map[string]*browserSession{"session-a": {owner: owner}}}
	handler := h.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := auth.FromContext(r.Context()); err != nil {
			t.Error("verified principal missing")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		name, token, session, header string
		status                       int
	}{
		{"missing token", "", "", "", 401},
		{"ABC cannot authenticate", "", "", "ABC", 401},
		{"old service secret", strings.Repeat("s", 32), "", "ABC", 401},
		{"valid without custom header", raw, "", "", 204},
		{"ABC is ignored", raw, "session-a", "ABC", 204},
		{"refresh", token(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(2 * time.Hour).Unix() }), "session-a", "", 204},
		{"different subject", token(func(c jwt.MapClaims) { c["sub"] = "user-b" }), "session-a", "ABC", 403},
		{"different client accepted", token(func(c jwt.MapClaims) { c["client_id"] = "client-b" }), "session-a", "", 204},
		{"unknown session", raw, "missing", "", 404},
		{"wrong issuer", token(func(c jwt.MapClaims) { c["iss"] = "https://other.example" }), "", "", 401},
		{"other audience accepted", token(func(c jwt.MapClaims) { c["aud"] = "id-token-client" }), "", "", 204},
		{"missing audience accepted", token(func(c jwt.MapClaims) { delete(c, "aud") }), "", "", 204},
		{"expired", token(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }), "", "", 401},
		{"missing expiry", token(func(c jwt.MapClaims) { delete(c, "exp") }), "", "", 401},
		{"missing scope", token(func(c jwt.MapClaims) { delete(c, "scope") }), "", "", 401},
		{"wrong scope", token(func(c jwt.MapClaims) { c["scope"] = "other:use" }), "", "", 401},
		{"future not before", token(func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }), "", "", 401},
		{"unknown client accepted", token(func(c jwt.MapClaims) { c["client_id"] = "unknown" }), "", "", 204},
		{"missing client accepted", token(func(c jwt.MapClaims) { delete(c, "client_id") }), "", "", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, method := range []string{"POST", "GET", "DELETE"} {
				req := httptest.NewRequest(method, "http://service.example/mcp", nil)
				if tc.token != "" {
					req.Header.Set("Authorization", "Bearer "+tc.token)
				}
				req.Header.Set("X-Mechanize-Owner", tc.header)
				req.Header.Set("Mcp-Session-Id", tc.session)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				if response.Code != tc.status {
					t.Fatalf("%s got %d want %d: %s", method, response.Code, tc.status, response.Body.String())
				}
				if tc.status == 401 && response.Header().Get("WWW-Authenticate") == "" {
					t.Fatal("missing bearer challenge")
				}
				if strings.Contains(response.Body.String(), raw) {
					t.Fatal("token leaked")
				}
			}
		})
	}
}

func TestMissingVerifierFailsClosed(t *testing.T) {
	response := httptest.NewRecorder()
	(&Host{}).HTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("anonymous request dispatched") })).ServeHTTP(response, httptest.NewRequest("POST", "http://localhost/mcp", nil))
	if response.Code != 503 {
		t.Fatal(response.Code)
	}
}
