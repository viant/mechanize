package host

import (
	"testing"

	"github.com/viant/mechanize/auth"
)

func TestStaticTextConfigRequiresExactEnrolledScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		user  User
		valid bool
	}{
		{"defaultDenied", User{Subject: "u"}, true},
		{"explicitApplication", User{Subject: "u", NativeBundles: []string{"com.apple.calculator"}, StaticTextBundles: []string{"com.apple.calculator"}}, true},
		{"desktopStillExplicit", User{Subject: "u", DesktopAccess: true, StaticTextBundles: []string{"com.apple.calculator"}}, true},
		{"outsideUserScope", User{Subject: "u", NativeBundles: []string{"com.apple.finder"}, StaticTextBundles: []string{"com.apple.calculator"}}, false},
		{"wildcardDenied", User{Subject: "u", DesktopAccess: true, StaticTextBundles: []string{"*"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{SourceRoot: t.TempDir(), StorageRoot: t.TempDir(), Users: []User{tc.user}, IdentityPolicy: auth.Policy{Issuer: "fixture", Audience: "fixture", Algorithms: []string{"HS256"}}}
			if err := c.Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
