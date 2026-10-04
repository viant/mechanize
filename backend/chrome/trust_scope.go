package chrome

import (
	"errors"
	"path/filepath"

	"github.com/viant/mechanize/auth/nativepeer"
)

const (
	TrustScopeProfile = "profile"
	TrustScopeDesktop = "desktop"
)

// NormalizeTrustScope preserves strict legacy profile enrollment by default.
// Only trusted operator enrollment may select desktop-wide browser trust.
func NormalizeTrustScope(scope string) (string, error) {
	switch scope {
	case "", TrustScopeProfile:
		return TrustScopeProfile, nil
	case TrustScopeDesktop:
		return TrustScopeDesktop, nil
	default:
		return "", errors.New("explicit supported Chrome trust scope required")
	}
}

func desktopProcessQualified(e *nativepeer.ChromeProcessEvidence) bool {
	return e != nil && e.KernelPeerQualified && e.NativeHost.PID > 0 && e.NativeHost.StartToken != "" && filepath.IsAbs(e.NativeHost.Executable) && e.ChromeParent.PID > 0 && e.ChromeParent.PID != e.NativeHost.PID && e.ChromeParent.StartToken != "" && filepath.IsAbs(e.ChromeParent.Executable) && e.NativeHost.UID == e.ChromeParent.UID && len(e.Ancestors) == 1 && e.Ancestors[0] == e.ChromeParent
}

// Called only while holding the broker mutex. Fixture qualification remains
// usable for fixtures, but production authority additionally excludes fixtures.
func channelScopeQualified(c *channel) bool {
	if c == nil || !c.scopeQualified {
		return false
	}
	switch c.grant.TrustScope {
	case TrustScopeProfile:
		return c.profileQualified
	case TrustScopeDesktop:
		return !c.profileQualified && c.grant.ProfileDirectory == "" && (c.fixtureOnly || desktopProcessQualified(c.processEvidence))
	default:
		return false
	}
}
