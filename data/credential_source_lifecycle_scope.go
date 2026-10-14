package data

import (
	"context"
	"github.com/viant/mechanize/auth"
	"strings"
	"sync/atomic"
)

type credentialSourceLifecycleKey struct{}
type credentialSourceLifecycleAuthority struct {
	actor   auth.Principal
	binding auth.ConsentBinding
	scope   CredentialProtectionScopeRecord
	guard   func(context.Context) error
	active  atomic.Bool
}

// WithCredentialSourceLifecycleAuthority reads only one retained predecessor's
// original metadata. The successor actor is unchanged. Protection closure still
// requires the separate complete-child source-absence seal; no input is granted.
// For a non-controller predecessor the host guard also proves its exact retained
// runtime owner/session has stopped, or an authenticated replacement executor has
// superseded its original fence. Cancellation or map/epoch absence alone is insufficient.
func WithCredentialSourceLifecycleAuthority(ctx context.Context, scope CredentialProtectionScopeRecord, guard func(context.Context) error) (context.Context, func(), error) {
	p, e := auth.FromContext(ctx)
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if e != nil || p.Validate() != nil || !p.HasScope("desktop:control") || p.ClientID == "" || p.Namespace != scope.Namespace || p.ClientID == scope.ClientID || scope.ClientID == "" || strings.HasPrefix(scope.ClientID, "controller:") && !deliveryHex.MatchString(strings.TrimPrefix(scope.ClientID, "controller:")) || scope.Validate() != nil || auth.NativeHuman(ctx) || !bound || binding.SessionID == "" || binding.GrantID == "" || binding.Purpose == "" || guard == nil || !credentialDeliveryGuard(ctx, guard) {
		return nil, nil, ErrCredentialDeliveryAuthority
	}
	if _, e = RequireScope(ctx, p.Namespace); e != nil {
		return nil, nil, e
	}
	a := &credentialSourceLifecycleAuthority{actor: p, binding: binding, scope: scope, guard: guard}
	a.active.Store(true)
	return context.WithValue(ctx, credentialSourceLifecycleKey{}, a), func() { a.active.Store(false) }, nil
}
func CredentialSourceLifecycleScope(ctx context.Context) (CredentialProtectionScopeRecord, bool) {
	a, ok := ctx.Value(credentialSourceLifecycleKey{}).(*credentialSourceLifecycleAuthority)
	p, e := auth.FromContext(ctx)
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if !ok || a == nil || !a.active.Load() || e != nil || p.Validate() != nil || p.Namespace != a.actor.Namespace || p.ClientID != a.actor.ClientID || !p.HasScope("desktop:control") || auth.NativeHuman(ctx) || !bound || binding != a.binding || !credentialDeliveryGuard(ctx, a.guard) {
		return CredentialProtectionScopeRecord{}, false
	}
	if _, e = RequireScope(ctx, p.Namespace); e != nil {
		return CredentialProtectionScopeRecord{}, false
	}
	return a.scope, true
}
func CredentialSourceLifecycleMatches(ctx context.Context, namespace, client, id string) bool {
	scope, ok := CredentialSourceLifecycleScope(ctx)
	return ok && scope.Namespace == namespace && scope.ClientID == client && scope.PreparationID == id
}
func credentialSourceLifecyclePreparationMatches(ctx context.Context, r CredentialPreparationRecord, birth string) bool {
	scope, ok := CredentialSourceLifecycleScope(ctx)
	return ok && scope.Namespace == r.Namespace && scope.ClientID == r.ClientID && scope.PreparationID == r.PreparationID && scope.Origin == r.Origin && scope.ChromeStartToken == birth
}
