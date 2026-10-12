package data

import (
	"context"
	"errors"

	"github.com/viant/mechanize/auth"
)

const ChromeReconnectBindingCapacity = 4096
const ChromeReconnectBindingPageSize = 128

type ChromeReconnectBindingFence struct{ BrokerEpoch, ChannelEpoch, ScopeHash string }
type ChromeReconnectBindingReadScope struct {
	ProfileChannel, BrowserInstance, ScopeHash string
}
type chromeReconnectBindingReadKey struct{}
type chromeReconnectBindingReadAuthority struct {
	principal auth.Principal
	scope     ChromeReconnectBindingReadScope
	guard     func(context.Context) error
}

// WithChromeReconnectBindingReadAuthority is called only by trusted lifecycle
// code after the signed process/channel and immutable pending lineage are
// verified. It grants no input or ledger write and never fabricates NativeHuman.
func WithChromeReconnectBindingReadAuthority(ctx context.Context, scope ChromeReconnectBindingReadScope, guard func(context.Context) error) (context.Context, error) {
	p, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || p.ClientID == "" || !p.HasScope("desktop:control") || guard == nil {
		return nil, auth.ErrUnauthorized
	}
	if _, err = RequireScope(ctx, p.Namespace); err != nil {
		return nil, err
	}
	if !retirementOpaque.MatchString(scope.ProfileChannel) || !retirementOpaque.MatchString(scope.BrowserInstance) || !retirementHash.MatchString(scope.ScopeHash) {
		return nil, errors.New("exact trusted reconnect channel scope required")
	}
	scoped := context.WithValue(ctx, chromeReconnectBindingReadKey{}, &chromeReconnectBindingReadAuthority{principal: p, scope: scope, guard: guard})
	if _, err = RequireChromeReconnectBindingReadAuthority(scoped); err != nil {
		return nil, err
	}
	return scoped, nil
}
func RequireChromeReconnectBindingReadAuthority(ctx context.Context) (ChromeReconnectBindingReadScope, error) {
	zero := ChromeReconnectBindingReadScope{}
	a, ok := ctx.Value(chromeReconnectBindingReadKey{}).(*chromeReconnectBindingReadAuthority)
	p, err := auth.FromContext(ctx)
	if !ok || a == nil || err != nil || p.Namespace != a.principal.Namespace || p.ClientID != a.principal.ClientID || !p.HasScope("desktop:control") {
		return zero, auth.ErrUnauthorized
	}
	if _, err = RequireScope(ctx, p.Namespace); err != nil {
		return zero, err
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if err = a.guard(ctx); err != nil {
		return zero, err
	}
	result := a.scope
	return result, ctx.Err()
}
func ValidateChromeReconnectBindingPage(ctx context.Context, namespace, profile, browser, scopeHash, afterID string) error {
	scope, err := RequireChromeReconnectBindingReadAuthority(ctx)
	if err != nil {
		return err
	}
	p, err := auth.FromContext(ctx)
	if err != nil || p.Namespace != namespace || scope.ProfileChannel != profile || scope.BrowserInstance != browser || scope.ScopeHash != scopeHash {
		return auth.ErrUnauthorized
	}
	if afterID != "" && !retirementHash.MatchString(afterID) {
		return auth.ErrUnauthorized
	}
	return nil
}
