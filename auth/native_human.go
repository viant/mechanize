package auth

import "context"

type nativeHumanKey struct{}

// WithNativeHuman is a trusted transport assertion. Call only after verifying
// the enrolled native console's signed peer identity and Scy admin credential.
// A scope claim or client-supplied bundle name alone is insufficient.
func WithNativeHuman(ctx context.Context) (context.Context, error) {
	p, err := FromContext(ctx)
	if err != nil || !p.HasScope("consent:admin") {
		return nil, ErrUnauthorized
	}
	return context.WithValue(ctx, nativeHumanKey{}, p.Namespace), nil
}

func NativeHuman(ctx context.Context) bool {
	p, err := FromContext(ctx)
	return err == nil && p.HasScope("consent:admin") && ctx.Value(nativeHumanKey{}) == p.Namespace
}
