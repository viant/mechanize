// Package auth binds verified Scy credentials to Mechanize's user namespace.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/viant/mcp/server/namespace"
)

var ErrUnauthorized = errors.New("verified identity is required")

type Principal struct {
	Issuer     string   `json:"issuer"`
	Subject    string   `json:"subject"`
	Tenant     string   `json:"tenant,omitempty"`
	Scopes     []string `json:"scopes"`
	Namespace  string   `json:"namespace"`
	ClientID   string   `json:"clientId,omitempty"`
	ClientName string   `json:"clientName,omitempty"`
}

// NewPrincipal accepts trusted identity facts, never tool-request identity fields.
func NewPrincipal(issuer, tenant, subject string, scopes []string) (Principal, error) {
	issuer, tenant, subject = strings.TrimSpace(issuer), strings.TrimSpace(tenant), strings.TrimSpace(subject)
	if issuer == "" || subject == "" {
		return Principal{}, ErrUnauthorized
	}
	canonical, _ := json.Marshal([]string{"mechanize.identity.v1", issuer, tenant, subject})
	digest := sha256.Sum256(canonical)
	return Principal{Issuer: issuer, Tenant: tenant, Subject: subject, Scopes: append([]string(nil), scopes...), Namespace: hex.EncodeToString(digest[:])}, nil
}
func (p Principal) HasScope(scope string) bool {
	for _, candidate := range p.Scopes {
		if candidate == scope {
			return true
		}
	}
	return false
}
func (p Principal) Validate() error {
	derived, err := NewPrincipal(p.Issuer, p.Tenant, p.Subject, p.Scopes)
	if err != nil || derived.Namespace != p.Namespace {
		return ErrUnauthorized
	}
	return nil
}

type principalKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	p.Scopes = append([]string(nil), p.Scopes...)
	return context.WithValue(ctx, principalKey{}, p)
}
func FromContext(ctx context.Context) (Principal, error) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	if !ok || p.Validate() != nil {
		return Principal{}, ErrUnauthorized
	}
	p.Scopes = append([]string(nil), p.Scopes...)
	return p, nil
}

// NamespaceProvider implements viant/mcp's namespace contract without its
// unverified-claims, token-hash, or anonymous/default fallback behavior.
type NamespaceProvider struct{}

func (NamespaceProvider) Namespace(ctx context.Context) (namespace.Descriptor, error) {
	p, err := FromContext(ctx)
	if err != nil {
		return namespace.Descriptor{}, err
	}
	return namespace.Descriptor{Name: p.Namespace, Kind: namespace.KindIdentity, Hash: p.Namespace, PathPrefix: p.Namespace, ShardedPath: p.Namespace[:2] + "/" + p.Namespace}, nil
}
