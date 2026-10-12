package consent

import "context"

type reusableGrantKey struct{}

// RequireReusableGrant only restricts admission. Metadata-only preparation of a
// multi-operation private credential session must not consume a one-shot grant
// before any input. The real stored decision is checked by Authorize; this marker
// confers no permission, substitutes no identity and changes no grant semantics.
func RequireReusableGrant(ctx context.Context) context.Context {
	return context.WithValue(ctx, reusableGrantKey{}, true)
}
