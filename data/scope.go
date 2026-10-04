// Package data defines trusted invocation scope and infrastructure configuration.
// Product operations are the generated components in its child packages.
package data

import (
	"context"
	"errors"
	"regexp"
)

type scopeKey struct{}
type Scope struct {
	Namespace  string
	LeaseEpoch int
}

var namespacePattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// WithScope is called only after the host verifies identity and desktop authority.
// It never accepts a client-selected namespace or DSN.
func WithScope(ctx context.Context, scope Scope) (context.Context, error) {
	if !namespacePattern.MatchString(scope.Namespace) {
		return nil, errors.New("verified opaque namespace required")
	}
	return context.WithValue(ctx, scopeKey{}, scope), nil
}
func RequireScope(ctx context.Context, namespace string) (Scope, error) {
	scope, ok := ctx.Value(scopeKey{}).(Scope)
	if !ok || scope.Namespace != namespace || !namespacePattern.MatchString(namespace) {
		return Scope{}, errors.New("data invocation scope denied")
	}
	return scope, nil
}

// CurrentScope returns the host-verified invocation scope, never a request field.
func CurrentScope(ctx context.Context) (Scope, bool) {
	scope, ok := ctx.Value(scopeKey{}).(Scope)
	if !ok || !namespacePattern.MatchString(scope.Namespace) {
		return Scope{}, false
	}
	return scope, true
}
