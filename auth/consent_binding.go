package auth

import "context"

// ConsentBinding contains caller intent, never a permission decision. Every
// dispatch must validate it against the private durable consent service.
type ConsentBinding struct {
	GrantID   string
	SessionID string
	Purpose   string
}
type consentBindingKey struct{}

func WithConsentBinding(ctx context.Context, b ConsentBinding) context.Context {
	return context.WithValue(ctx, consentBindingKey{}, b)
}
func ConsentBindingFromContext(ctx context.Context) (ConsentBinding, bool) {
	b, ok := ctx.Value(consentBindingKey{}).(ConsentBinding)
	return b, ok && b.SessionID != ""
}
