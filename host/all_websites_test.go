package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
	"testing"
)

func TestBrowserWideConsentRequiresTrustedEnrollmentAndDesktopCeiling(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "browser-wide", []string{"desktop:control"})
	h := &Host{users: map[string]User{p.Namespace: {DesktopAccess: true}}, chromeAllWebsites: map[string]bool{p.Namespace: true}}
	browser := consent.Scope{Kind: "browser", BundleID: "com.google.Chrome"}
	for _, origin := range []string{"http://ordinary.test", "https://second.test"} {
		scope, err := h.operationConsentScope(p, model.Surface{Kind: "web", Origin: origin})
		if err != nil || scope != browser {
			t.Fatalf("not mapped to browser approval: %+v %v", scope, err)
		}
	}
	native, _ := h.operationConsentScope(p, model.Surface{Kind: "native", BundleID: "com.google.Chrome"})
	if browser.Covers(native) || native.Covers(browser) || browser.Covers(consent.Scope{Kind: "desktop"}) {
		t.Fatal("browser approval became native authority")
	}
	if !(consent.Scope{Kind: "desktop"}).Covers(browser) {
		t.Fatal("explicit desktop grant lost coverage")
	}
	for _, surface := range []model.Surface{{Kind: "web", Origin: "https://u:p@example.test"}, {Kind: "web", Origin: "chrome://settings"}, {Kind: "web", Origin: "https://example.test", BundleID: "com.google.Chrome"}} {
		if _, err := h.operationConsentScope(p, surface); err == nil {
			t.Fatal("invalid website mapped")
		}
	}
	for _, enabled := range []bool{false, true} {
		h.chromeAllWebsites[p.Namespace] = enabled
		h.users[p.Namespace] = User{DesktopAccess: !enabled}
		scope, err := h.operationConsentScope(p, model.Surface{Kind: "web", Origin: "https://exact.test"})
		if err != nil || scope.Kind != "origin" {
			t.Fatal("scope broadened without both enrollment and ceiling")
		}
	}
}
func TestAllWebsitesRetirementDigestDistinctAndAmbiguousRejected(t *testing.T) {
	ctx, s, primitives := evidenceFixture(t)
	provider, err := newChromeRetirementEvidenceProvider("broker requirement", primitives)
	if err != nil {
		t.Fatal(err)
	}
	_, exact, err := provider(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	s.AllWebsites = true
	if _, _, err = provider(ctx, s); err == nil {
		t.Fatal("mixed all-websites/exact origins accepted")
	}
	s.Origins = nil
	_, all, err := provider(ctx, s)
	if err != nil || all.OriginScopeDigest == exact.OriginScopeDigest {
		t.Fatalf("broad scope not bound: %+v %v", all, err)
	}
}

func TestAllWebsitesConfigRequiresOperatorDesktopCeiling(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	c := Config{SourceRoot: "/fixture/source", StorageRoot: "/fixture/storage", IdentityPolicy: auth.Policy{Issuer: "fixture", Audience: "fixture", Algorithms: []string{"HS256"}}, Users: []User{{Subject: "owner", DesktopAccess: true}}, Chrome: &chrome.Config{Grants: []chrome.Enrollment{{Principal: p, AllWebsites: true}}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Users[0].DesktopAccess = false
	if c.Validate() == nil {
		t.Fatal("all websites bypassed operator ceiling")
	}
	c.Users[0].DesktopAccess = true
	c.Chrome.Grants[0].Origins = []string{"https://exact.test"}
	if c.Validate() == nil {
		t.Fatal("ambiguous enrollment accepted")
	}
}
func TestAllWebsitesControlAndCapabilitiesUseObservedOrigin(t *testing.T) {
	f := newWebControlFixture(t)
	f.enrollment.Profiles[0].AllWebsites = true
	f.enrollment.Profiles[0].Origins = nil
	origin := "http://ordinary.test"
	f.enrollment.Profiles[0].ObservedOrigins = []string{origin}
	f.ready.Authority.Document.Origin = origin
	surface := model.Surface{Kind: "web", Origin: origin}
	if _, err := f.manager.qualify(f.ctx, f.principal, surface); err != nil {
		t.Fatal(err)
	}
	if !f.manager.Capabilities(f.ctx, f.principal)["web:element.press"] {
		t.Fatal("all websites lost capabilities")
	}
	f.enrollment.Profiles[0].Origins = []string{origin}
	if _, err := f.manager.qualify(f.ctx, f.principal, surface); err == nil {
		t.Fatal("ambiguous all-websites policy accepted")
	}
	if f.dispatches != 0 {
		t.Fatal("qualification dispatched input")
	}
}

func TestBrowserConsentRequestCannotEnableAllWebsites(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "browser-request", []string{"desktop:control"})
	ctx := auth.WithPrincipal(context.Background(), p)
	h := &Host{users: map[string]User{p.Namespace: {DesktopAccess: true}}, chromeAllWebsites: map[string]bool{}}
	scope := consent.Scope{Kind: "browser", BundleID: "com.google.Chrome"}
	if h.ConsentPolicy(ctx, p, scope, []consent.Mode{consent.Control}, 60) == nil {
		t.Fatal("request enabled broad enrollment")
	}
	h.chromeAllWebsites[p.Namespace] = true
	if err := h.ConsentPolicy(ctx, p, scope, []consent.Mode{consent.Control}, 60); err != nil {
		t.Fatal(err)
	}
	h.users[p.Namespace] = User{DesktopAccess: false}
	if h.ConsentPolicy(ctx, p, scope, []consent.Mode{consent.Control}, 60) == nil {
		t.Fatal("request bypassed current operator ceiling")
	}
}
