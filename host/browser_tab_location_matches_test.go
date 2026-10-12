package host

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

type tabLocationFixture struct {
	calls int
	ctx   context.Context
	check func(context.Context, auth.Principal, string, string, string)
}

func (f *tabLocationFixture) MatchTabLocation(ctx context.Context, p auth.Principal, tab, origin, path string) (chrome.TabLocationMatch, error) {
	f.calls++
	f.ctx = ctx
	if f.check != nil {
		f.check(ctx, p, tab, origin, path)
	}
	return chrome.TabLocationMatch{Available: true, MatchesExpectedOrigin: true, PathChecked: true, MatchesExpectedPath: true, Reason: "none"}, nil
}

// Invoked by the existing real-consent protected-origin fixture, after a grant
// exists and before its final session cancellation. No mock bypass of consent.
func checkProtectedExactTabComparison(t *testing.T, h *Host, ctx context.Context, p auth.Principal, sessionID, origin string) {
	t.Helper()
	in := gateway.BrowserTabLocationMatchesInput{SessionID: sessionID, TabHandle: "profile/browser/7", ExpectedOrigin: origin, ExpectedPath: "/connect/Login/error"}
	f := &tabLocationFixture{check: func(c context.Context, actor auth.Principal, tab, wantOrigin, path string) {
		cb, ok := auth.ConsentBindingFromContext(c)
		if !ok || cb.SessionID != sessionID || cb.GrantID == "" || actor.ClientID != p.ClientID || tab != in.TabHandle || wantOrigin != origin || path != in.ExpectedPath || auth.NativeHuman(c) {
			t.Fatal("metadata authority widened")
		}
	}}
	out, e := h.matchTabLocation(ctx, p, in, f)
	if e != nil || !out.MatchesExpectedPath || f.calls != 1 {
		t.Fatal("protected exact-tab comparison failed", e)
	}
	if f.ctx.Err() == nil {
		t.Fatal("comparison retained consent lease")
	}
	if _, e = h.AuthorizeOperation(ctx, p, model.Surface{Kind: "web", Origin: origin}, false, consent.Observe); !errors.Is(e, vault.ErrEntryProtected) {
		t.Fatal("metadata comparison released protection", e)
	}
	for _, alter := range []func(*gateway.BrowserTabLocationMatchesInput){func(i *gateway.BrowserTabLocationMatchesInput) { i.SessionID = "foreign" }, func(i *gateway.BrowserTabLocationMatchesInput) { i.ExpectedOrigin = "https://outside.test" }, func(i *gateway.BrowserTabLocationMatchesInput) { i.ExpectedPath = "/login?secret=x" }, func(i *gateway.BrowserTabLocationMatchesInput) { i.TabHandle = "https://foreign/" }} {
		bad := in
		alter(&bad)
		if _, e = h.matchTabLocation(ctx, p, bad, f); e == nil || f.calls != 1 {
			t.Fatal("invalid metadata scope admitted")
		}
	}
}
