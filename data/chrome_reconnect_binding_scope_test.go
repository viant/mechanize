package data

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
)

func TestReconnectReaderAuthorityIsExactScopedRevocableAndNotHumanImpersonation(t *testing.T) {
	p, e := auth.NewPrincipal("fixture", "", "reconnect-authority", []string{"desktop:control"})
	if e != nil {
		t.Fatal(e)
	}
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx, e = WithScope(ctx, Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if e != nil {
		t.Fatal(e)
	}
	scope := ChromeReconnectBindingReadScope{ProfileChannel: "profile", BrowserInstance: "browser", ScopeHash: strings.Repeat("a", 64)}
	if _, e = WithChromeReconnectBindingReadAuthority(ctx, scope, nil); e == nil {
		t.Fatal("missing native guard accepted")
	}
	live := true
	calls := 0
	sealed, e := WithChromeReconnectBindingReadAuthority(ctx, scope, func(context.Context) error {
		calls++
		if !live {
			return auth.ErrUnauthorized
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if auth.NativeHuman(sealed) {
		t.Fatal("read capability impersonated human")
	}
	for _, mode := range []string{"namespace", "profile", "browser", "scope", "cursor", "client"} {
		ns, profile, browser, hash, cursor := p.Namespace, scope.ProfileChannel, scope.BrowserInstance, scope.ScopeHash, ""
		current := sealed
		switch mode {
		case "namespace":
			ns = strings.Repeat("b", 64)
		case "profile":
			profile = "foreign"
		case "browser":
			browser = "foreign"
		case "scope":
			hash = strings.Repeat("c", 64)
		case "cursor":
			cursor = "not-a-key"
		case "client":
			foreign := p
			foreign.ClientID = "foreign"
			current = auth.WithPrincipal(sealed, foreign)
		}
		if e = ValidateChromeReconnectBindingPage(current, ns, profile, browser, hash, cursor); !errors.Is(e, auth.ErrUnauthorized) {
			t.Fatal("foreign page accepted", mode, e)
		}
	}
	if e = ValidateChromeReconnectBindingPage(sealed, p.Namespace, scope.ProfileChannel, scope.BrowserInstance, scope.ScopeHash, ""); e != nil {
		t.Fatal(e)
	}
	live = false
	if _, e = RequireChromeReconnectBindingReadAuthority(sealed); !errors.Is(e, auth.ErrUnauthorized) {
		t.Fatal("revoked authority accepted", e)
	}
	if calls < 2 {
		t.Fatal("guard was not revalidated")
	}
}
