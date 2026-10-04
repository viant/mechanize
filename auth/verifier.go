package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/scy/auth/jwt/verifier"
)

type Policy struct {
	// Clients maps signed client_id claims to operator-enrolled display names.
	Clients        map[string]string `json:"clients,omitempty"`
	Issuer         string            `json:"issuer"`
	Audience       string            `json:"audience"`
	Algorithms     []string          `json:"algorithms"`
	RequiredScopes []string          `json:"requiredScopes"`
	TenantClaim    string            `json:"tenantClaim,omitempty"`
}
type Verifier struct {
	scy    *verifier.Service
	policy Policy
}

func NewVerifier(ctx context.Context, cfg *verifier.Config, policy Policy) (*Verifier, error) {
	if cfg == nil || strings.TrimSpace(policy.Issuer) == "" || strings.TrimSpace(policy.Audience) == "" || len(policy.Algorithms) == 0 {
		return nil, errors.New("Scy keys and explicit issuer, audience and algorithms are required")
	}
	for _, a := range policy.Algorithms {
		if a == "" || a == "none" {
			return nil, errors.New("unsigned token algorithms are forbidden")
		}
	}
	service := verifier.New(cfg)
	if err := service.Init(ctx); err != nil {
		return nil, fmt.Errorf("initialize Scy credential verifier: %w", err)
	}
	clients := map[string]string{}
	for id, name := range policy.Clients {
		if strings.TrimSpace(id) == "" || strings.TrimSpace(name) == "" || len(id) > 256 || len(name) > 512 {
			return nil, errors.New("bounded enrolled client identity required")
		}
		clients[id] = name
	}
	policy.Clients = clients
	policy.Algorithms = append([]string(nil), policy.Algorithms...)
	policy.RequiredScopes = append([]string(nil), policy.RequiredScopes...)
	return &Verifier{scy: service, policy: policy}, nil
}
func (v *Verifier) Verify(ctx context.Context, raw string) (Principal, error) {
	if raw == "" || len(raw) > 32768 {
		return Principal{}, ErrUnauthorized
	}
	token, err := v.scy.Validate(ctx, raw)
	if err != nil || token == nil || !token.Valid {
		return Principal{}, ErrUnauthorized
	}
	allowed := false
	for _, alg := range v.policy.Algorithms {
		if token.Method.Alg() == alg {
			allowed = true
			break
		}
	}
	if !allowed {
		return Principal{}, ErrUnauthorized
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return Principal{}, ErrUnauthorized
	}
	issuer, err := claims.GetIssuer()
	if err != nil || issuer != v.policy.Issuer {
		return Principal{}, ErrUnauthorized
	}
	aud, err := claims.GetAudience()
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	matches := false
	for _, a := range aud {
		if a == v.policy.Audience {
			matches = true
		}
	}
	if !matches {
		return Principal{}, ErrUnauthorized
	}
	expiry, err := claims.GetExpirationTime()
	if err != nil || expiry == nil || !time.Now().Before(expiry.Time) {
		return Principal{}, ErrUnauthorized
	}
	nbf, err := claims.GetNotBefore()
	if err != nil || (nbf != nil && time.Now().Before(nbf.Time)) {
		return Principal{}, ErrUnauthorized
	}
	subject, err := claims.GetSubject()
	if err != nil || strings.TrimSpace(subject) == "" {
		return Principal{}, ErrUnauthorized
	}
	tenant := ""
	if v.policy.TenantClaim != "" {
		value, exists := claims[v.policy.TenantClaim]
		if !exists {
			return Principal{}, ErrUnauthorized
		}
		tenant, ok = value.(string)
		if !ok || strings.TrimSpace(tenant) == "" {
			return Principal{}, ErrUnauthorized
		}
	}
	scopes := []string{}
	if value, exists := claims["scope"]; exists {
		text, valid := value.(string)
		if !valid {
			return Principal{}, ErrUnauthorized
		}
		scopes = strings.Fields(text)
	}
	principal, err := NewPrincipal(issuer, tenant, subject, scopes)
	if err != nil {
		return Principal{}, err
	}
	for _, scope := range v.policy.RequiredScopes {
		if !principal.HasScope(scope) {
			return Principal{}, ErrUnauthorized
		}
	}
	if len(v.policy.Clients) > 0 {
		id, valid := claims["client_id"].(string)
		name, enrolled := v.policy.Clients[id]
		if !valid || !enrolled {
			return Principal{}, ErrUnauthorized
		}
		principal.ClientID, principal.ClientName = id, name
	}
	return principal, nil
}

// Middleware performs cryptographic verification before any namespace resolution.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.Header.Get("Authorization")
		parts := strings.Fields(value)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "verified identity is required", http.StatusUnauthorized)
			return
		}
		p, err := v.Verify(r.Context(), parts[1])
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
			http.Error(w, "invalid credential", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}
