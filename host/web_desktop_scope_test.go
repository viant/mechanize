package host

import (
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/backend/chrome"
)

func TestDesktopBrowserEnrollmentRequiresExplicitDesktopUser(t *testing.T) {
	p, err := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	fixture := func() Config {
		return Config{SourceRoot: "/fixture/source", StorageRoot: "/fixture/storage", IdentityPolicy: auth.Policy{Issuer: "fixture", Audience: "fixture", Algorithms: []string{"HS256"}}, Users: []User{{Subject: "owner", DesktopAccess: true}}, Chrome: &chrome.Config{ProcessTrust: &nativepeer.ChromeProcessPolicy{}, Grants: []chrome.Enrollment{{Principal: p, TrustScope: chrome.TrustScopeDesktop}}}}
	}
	if err := fixture().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*Config)
	}{
		{"no blanket user", func(c *Config) { c.Users[0].DesktopAccess = false }},
		{"other namespace", func(c *Config) { c.Chrome.Grants[0].Principal.Namespace = "other" }},
		{"fixture enrollment", func(c *Config) { c.Chrome.FixtureEnrollment = true }},
		{"no process policy", func(c *Config) { c.Chrome.ProcessTrust = nil }},
		{"unknown mode", func(c *Config) { c.Chrome.Grants[0].TrustScope = "all" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := fixture()
			test.change(&c)
			if c.Validate() == nil {
				t.Fatal("unqualified desktop browser enrollment accepted")
			}
		})
	}
}

func TestWebDesktopScopeIsExplicitAndDoesNotClaimProfileIsolation(t *testing.T) {
	f := newWebControlFixture(t)
	f.enrollment.Profiles[0].TrustScope = chrome.TrustScopeDesktop
	f.ready.Authority.TrustScope = chrome.TrustScopeDesktop
	f.ready.ProfileQualified = false
	f.ready.ScopeQualified = true
	ready, err := f.manager.qualify(f.ctx, f.principal, f.step.Target.Surface)
	if err != nil || ready.ProfileQualified || !ready.ScopeQualified || ready.Authority.TrustScope != chrome.TrustScopeDesktop {
		t.Fatalf("desktop scope qualification: %+v %v", ready, err)
	}
	if f.dispatches != 0 {
		t.Fatal("qualification dispatched input")
	}
	for _, test := range []struct {
		name   string
		change func(*webControlFixture)
	}{
		{"profile grant cannot upgrade", func(f *webControlFixture) { f.enrollment.Profiles[0].TrustScope = "" }},
		{"scope proof missing", func(f *webControlFixture) { f.ready.ScopeQualified = false }},
		{"false profile claim", func(f *webControlFixture) { f.ready.ProfileQualified = true }},
		{"unknown authority scope", func(f *webControlFixture) { f.ready.Authority.TrustScope = "all" }},
		{"renderer not ready", func(f *webControlFixture) { f.ready.ExecutorQualified = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			other := newWebControlFixture(t)
			other.enrollment.Profiles[0].TrustScope = chrome.TrustScopeDesktop
			other.ready.Authority.TrustScope = chrome.TrustScopeDesktop
			other.ready.ProfileQualified = false
			other.ready.ScopeQualified = true
			test.change(other)
			if _, err := other.manager.qualify(other.ctx, other.principal, other.step.Target.Surface); err == nil {
				t.Fatal("mismatched or unqualified scope accepted")
			}
			if other.dispatches != 0 {
				t.Fatal("rejected scope dispatched input")
			}
		})
	}
}
