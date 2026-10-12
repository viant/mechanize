package data

import (
	"context"
	"strings"
	"sync/atomic"

	"github.com/viant/mechanize/auth"
)

type credentialPreflightLifecycleKey struct{}
type credentialPreflightLifecycleAuthority struct {
	actor   auth.Principal
	binding auth.ConsentBinding
	scope   CredentialProtectionScopeRecord
	guard   func(context.Context) error
	active  atomic.Bool
}

// WithCredentialPreflightLifecycleAuthority permits only metadata read and
// zero-child protection closure for one abandoned controller preparation. The
// actual successor principal and current consent remain unchanged. It grants
// no original session, delivery, Vault, renderer or UNKNOWN resolution authority.
func WithCredentialPreflightLifecycleAuthority(ctx context.Context, scope CredentialProtectionScopeRecord, guard func(context.Context) error) (context.Context, func(), error) {
	p, e := auth.FromContext(ctx)
	b, ok := auth.ConsentBindingFromContext(ctx)
	minimal := CredentialProtectionScopeRecord{Namespace: scope.Namespace, ClientID: scope.ClientID, PreparationID: scope.PreparationID, Origin: scope.Origin}
	if e != nil || p.Validate() != nil || !p.HasScope("desktop:control") || p.ClientID == "" || p.Namespace != scope.Namespace || p.ClientID == scope.ClientID || !strings.HasPrefix(scope.ClientID, "controller:") || len(scope.ClientID) != len("controller:")+64 || !deliveryHex.MatchString(strings.TrimPrefix(scope.ClientID, "controller:")) || scope != minimal || !scope.ValidOrigin() || !deliveryHex.MatchString(scope.PreparationID) || auth.NativeHuman(ctx) || !ok || b.SessionID == "" || b.GrantID == "" || b.Purpose == "" || guard == nil || !credentialDeliveryGuard(ctx, guard) {
		return nil, nil, ErrCredentialDeliveryAuthority
	}
	if _, e = RequireScope(ctx, p.Namespace); e != nil {
		return nil, nil, e
	}
	a := &credentialPreflightLifecycleAuthority{actor: p, binding: b, scope: scope, guard: guard}
	a.active.Store(true)
	return context.WithValue(ctx, credentialPreflightLifecycleKey{}, a), func() { a.active.Store(false) }, nil
}
func CredentialPreflightLifecycleScope(ctx context.Context) (CredentialProtectionScopeRecord, bool) {
	a, ok := ctx.Value(credentialPreflightLifecycleKey{}).(*credentialPreflightLifecycleAuthority)
	p, e := auth.FromContext(ctx)
	b, bound := auth.ConsentBindingFromContext(ctx)
	if !ok || a == nil || !a.active.Load() || e != nil || p.Validate() != nil || p.Namespace != a.actor.Namespace || p.ClientID != a.actor.ClientID || !p.HasScope("desktop:control") || auth.NativeHuman(ctx) || !bound || b != a.binding || !credentialDeliveryGuard(ctx, a.guard) {
		return CredentialProtectionScopeRecord{}, false
	}
	if _, e = RequireScope(ctx, p.Namespace); e != nil {
		return CredentialProtectionScopeRecord{}, false
	}
	return a.scope, true
}
func CredentialPreflightLifecycleMatches(ctx context.Context, namespace, client, id string) bool {
	scope, ok := CredentialPreflightLifecycleScope(ctx)
	return ok && scope.Namespace == namespace && scope.ClientID == client && scope.PreparationID == id
}

func credentialPreflightLifecyclePreparationMatches(ctx context.Context, r CredentialPreparationRecord) bool {
	scope, ok := CredentialPreflightLifecycleScope(ctx)
	return ok && scope.Namespace == r.Namespace && scope.ClientID == r.ClientID && scope.PreparationID == r.PreparationID && scope.Origin == r.Origin
}
