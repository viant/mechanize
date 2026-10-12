package host

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

type focusedOriginFixture struct {
	reads   int
	context context.Context
	check   func(context.Context, auth.Principal, string)
}

func (f *focusedOriginFixture) MatchFocusedOrigin(ctx context.Context, p auth.Principal, origin string) (chrome.FocusedOriginMatch, error) {
	f.reads++
	f.context = ctx
	if f.check != nil {
		f.check(ctx, p, origin)
	}
	return chrome.FocusedOriginMatch{Available: true, MatchesExpectedOrigin: true, Reason: "none", WindowFocused: true, Evidence: "extensionFocusedTab", TabHandle: "profile/browser/7"}, nil
}

func TestHostFocusedOriginReadDuringProtectionRetainsRealConsent(t *testing.T) {
	p, err := auth.NewPrincipal("fixture", "", "origin-owner", []string{"desktop:observe", "consent:admin"})
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID = "origin-client"
	p.ClientName = "Origin fixture"
	ctx := auth.WithPrincipal(context.Background(), p)
	rt, err := automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		t.Fatal("metadata read dispatched input")
		return automation.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := rt.Open(ctx, "metadata comparison")
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx, session.SessionID)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session.SessionID, Purpose: "Compare focused browser origin"})
	_, file, _, _ := runtime.Caller(0)
	scoped, _ := data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	server, err := datahost.Open(scoped, filepath.Dir(filepath.Dir(file)), t.TempDir(), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	gate, err := vault.NewGuardedExposureGate(func(context.Context) error { return vault.ErrEntryProtected })
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{Runtime: rt, users: map[string]User{p.Namespace: {Subject: p.Subject, WebOrigins: []string{"https://fixture.test"}}}, vaultExposure: gate}
	h.consent, err = NewConsentBroker(ConsentBrokerOptions{Invoke: func(c context.Context, _ auth.Principal, r exec.ComponentRequest) (any, error) {
		return server.InvokeComponent(c, r)
	}, Enrolled: h.enrolled, SessionOwned: rt.CheckSession, Policy: h.ConsentPolicy})
	if err != nil {
		t.Fatal(err)
	}
	reader := &focusedOriginFixture{}
	origin := "https://fixture.test"
	if _, err = h.matchFocusedOrigin(ctx, p, origin, reader); err == nil || reader.reads != 0 {
		t.Fatal("comparison bypassed missing consent")
	}
	request, err := h.consent.Request(ctx, p, session.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "origin", Origin: origin}, Modes: []consent.Mode{consent.Observe}, Purpose: "Compare focused browser origin", DurationSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowUntilRevoked})
	if _, err = h.consent.NativeRPC(human, "decide", decision); err != nil {
		t.Fatal(err)
	}
	surface := model.Surface{Kind: "web", Origin: origin}
	if _, err = h.AuthorizeOperation(ctx, p, surface, false, consent.Observe); !errors.Is(err, vault.ErrEntryProtected) {
		t.Fatal("ordinary observation lost protection", err)
	}
	reader.check = func(c context.Context, actor auth.Principal, expected string) {
		if actor.ClientID != p.ClientID || expected != origin || auth.NativeHuman(c) {
			t.Fatal("metadata authority widened")
		}
		binding, ok := auth.ConsentBindingFromContext(c)
		if !ok || binding.GrantID == "" || binding.SessionID != session.SessionID {
			t.Fatal("metadata lacked actual consent")
		}
	}
	got, err := h.matchFocusedOrigin(ctx, p, origin, reader)
	if err != nil || !got.Available || !got.MatchesExpectedOrigin || got.Evidence != "extensionFocusedTab" || reader.reads != 1 {
		t.Fatal("protected metadata unavailable", err)
	}
	if reader.context.Err() == nil {
		t.Fatal("metadata consent lease retained after return")
	}
	if _, err = h.AuthorizeOperation(ctx, p, surface, false, consent.Observe); !errors.Is(err, vault.ErrEntryProtected) {
		t.Fatal("comparison cleared protection", err)
	}
	checkProtectedExactTabComparison(t, h, ctx, p, session.SessionID, origin)
	unavailable, err := h.BrowserLocationMatches(ctx, p, origin)
	if err != nil || unavailable.Available || unavailable.Reason != "noQualifiedChannel" {
		t.Fatal("missing gateway did not report closed unavailability", err)
	}
	foreign := p
	foreign.ClientID = "foreign-client"
	otherCtx := auth.WithPrincipal(ctx, foreign)
	invalid := []struct {
		ctx    context.Context
		p      auth.Principal
		origin string
	}{
		{ctx, foreign, origin}, {otherCtx, foreign, origin},
		{auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "foreign-session", Purpose: "Compare focused browser origin"}), p, origin},
		{auth.WithPrincipal(context.Background(), p), p, origin},
		{ctx, p, "https://outside.test"}, {ctx, p, origin + "/private"},
	}
	for _, tc := range invalid {
		if _, err = h.matchFocusedOrigin(tc.ctx, tc.p, tc.origin, reader); err == nil || reader.reads != 1 {
			t.Fatal("invalid metadata authority reached reader", err)
		}
	}

	// An already-cancelled request cannot publish fresh evidence.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = h.matchFocusedOrigin(canceled, p, origin, reader); err == nil {
		t.Fatal("canceled request published metadata")
	}
	reader.check = func(context.Context, auth.Principal, string) {
		if err := rt.Close(ctx, session.SessionID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = h.matchFocusedOrigin(ctx, p, origin, reader); err == nil {
		t.Fatal("closed session published comparison")
	}
}
