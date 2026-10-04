package host

import (
	"encoding/json"
	"errors"
	"io"
	"path/filepath"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/security/keychain"
	"github.com/viant/mechanize/session"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
)

type User struct {
	DesktopAccess    bool                `json:"desktopAccess,omitempty"`
	RecordingAllowed bool                `json:"recordingAllowed,omitempty"`
	Subject          string              `json:"subject"`
	Tenant           string              `json:"tenant,omitempty"`
	NativeBundles    []string            `json:"nativeBundles"`
	WebOrigins       []string            `json:"webOrigins"`
	ValueIdentifiers map[string][]string `json:"valueIdentifiers,omitempty"`
	// StaticTextBundles permits bounded, noneditable AXStaticText reads only.
	StaticTextBundles []string `json:"staticTextBundles,omitempty"`
}
type NativeConsoleConfig struct {
	SocketPath            string `json:"socketPath"`
	DesignatedRequirement string `json:"designatedRequirement"`
	ExpectedUID           uint32 `json:"expectedUID"`
}
type ArtifactConfig struct {
	SourceKeyReference  string                  `json:"sourceKeyReference"`
	KeyResources        map[string]scy.Resource `json:"keyResources"`
	MaxBytes            int64                   `json:"maxBytes"`
	NamespaceQuotaBytes int64                   `json:"namespaceQuotaBytes"`
}

// NativeLaunchConfig enrolls the launch or semantic helper profile. Keyboard
// routes require separate opt-ins; all actions retain normal consent checks.
type NativeLaunchConfig struct {
	WindowFrameClick  bool    `json:"windowFrameClick,omitempty"`
	SessionKeyboard   bool    `json:"sessionKeyboard,omitempty"`
	TargetedKeyboard  bool    `json:"targetedKeyboard,omitempty"`
	Mode              string  `json:"mode,omitempty"`
	LockPath          string  `json:"lockPath"`
	HelperRequirement string  `json:"helperRequirement"`
	ExpectedUID       *uint32 `json:"expectedUID"`
}
type ChromeRetirementConfig struct {
	BrokerRequirement string `json:"brokerRequirement"`
}

type Config struct {
	ChromeRetirement           *ChromeRetirementConfig `json:"chromeRetirement,omitempty"`
	NativeEffectReconciliation []string                `json:"nativeEffectReconciliation,omitempty"`
	NativeLaunch               *NativeLaunchConfig     `json:"nativeLaunch,omitempty"`
	Artifacts                  *ArtifactConfig         `json:"artifacts,omitempty"`
	NativeConsole              *NativeConsoleConfig    `json:"nativeConsole,omitempty"`
	Keychain                   *keychain.Options       `json:"keychain,omitempty"`
	SourceRoot                 string                  `json:"sourceRoot"`
	StorageRoot                string                  `json:"storageRoot"`
	NativeHelper               string                  `json:"nativeHelper,omitempty"`
	Keys                       verifier.Config         `json:"keys"`
	IdentityPolicy             auth.Policy             `json:"identityPolicy"`
	StdioCredential            *scy.Resource           `json:"stdioCredential,omitempty"`
	Users                      []User                  `json:"users"`
	Chrome                     *chrome.Config          `json:"chrome,omitempty"`
	MaxUsers                   int                     `json:"maxUsers,omitempty"`
}

func DecodeConfig(reader io.Reader) (Config, error) {
	var c Config
	d := json.NewDecoder(io.LimitReader(reader, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return c, errors.New("trailing configuration input")
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.ChromeRetirement != nil && (c.Chrome == nil || c.Chrome.FixtureEnrollment || c.Chrome.ProcessTrust == nil || !retirementRequirement(c.ChromeRetirement.BrokerRequirement)) {
		return errors.New("retirement requires signed Chrome enrollment and trusted broker requirement")
	}

	if c.NativeLaunch != nil {
		if (c.NativeLaunch.TargetedKeyboard || c.NativeLaunch.SessionKeyboard || c.NativeLaunch.WindowFrameClick) && c.NativeLaunch.Mode != "semantic" {
			return errors.New("native input routes require explicitly enrolled semantic profile")
		}
		if c.NativeLaunch.Mode != "" && c.NativeLaunch.Mode != "launch" && c.NativeLaunch.Mode != "semantic" {
			return errors.New("native development mode must be launch or semantic")
		}
		if c.NativeHelper == "" || !filepath.IsAbs(c.NativeLaunch.LockPath) || c.NativeLaunch.HelperRequirement == "" || c.NativeLaunch.ExpectedUID == nil {
			return errors.New("native launch requires fixed helper, shared desktop fence, exact signed requirement and explicit UID")
		}
	}
	if !filepath.IsAbs(c.SourceRoot) || !filepath.IsAbs(c.StorageRoot) {
		return errors.New("absolute Datly source/storage roots required")
	}
	if c.NativeHelper != "" && !filepath.IsAbs(c.NativeHelper) {
		return errors.New("absolute native helper path required")
	}
	if c.Artifacts != nil {
		a := c.Artifacts
		if a.SourceKeyReference == "" || len(a.SourceKeyReference) > 256 || a.MaxBytes <= 0 || a.MaxBytes > 1<<30 || a.NamespaceQuotaBytes < a.MaxBytes {
			return errors.New("artifacts require an explicit key version, bounded byte limit and namespace quota")
		}
		if _, ok := a.KeyResources[a.SourceKeyReference]; !ok {
			return errors.New("artifact write key version is not enrolled")
		}
		for version, resource := range a.KeyResources {
			if version == "" || len(version) > 256 || resource.URL == "" || resource.Fallback != nil || len(resource.Data) != 0 {
				return errors.New("artifact keys require fixed Scy resource references without inline data or fallback")
			}
		}
	}
	if c.NativeConsole != nil {
		if !filepath.IsAbs(c.NativeConsole.SocketPath) || c.NativeConsole.DesignatedRequirement == "" {
			return errors.New("native console requires fixed absolute socket and explicit signed peer requirement")
		}
	}
	if len(c.Users) == 0 || c.IdentityPolicy.Issuer == "" || c.IdentityPolicy.Audience == "" || len(c.IdentityPolicy.Algorithms) == 0 {
		return errors.New("explicit users and identity policy required")
	}
	seen := map[string]bool{}
	desktopUsers := map[string]bool{}
	for _, u := range c.Users {
		if len(u.StaticTextBundles) > 0 {
			if _, err := (session.Scope{AllowedBundles: u.StaticTextBundles}).Normalize(); err != nil {
				return errors.New("static text reads require exact native application bundles")
			}
			for _, bundle := range u.StaticTextBundles {
				allowed := u.DesktopAccess
				for _, nativeBundle := range u.NativeBundles {
					allowed = allowed || bundle == nativeBundle
				}
				if !allowed {
					return errors.New("static text application outside enrolled user scope")
				}
			}
		}
		p, err := auth.NewPrincipal(c.IdentityPolicy.Issuer, u.Tenant, u.Subject, nil)
		if err != nil {
			return err
		}
		if seen[p.Namespace] {
			return errors.New("duplicate enrolled user")
		}
		seen[p.Namespace] = true
		desktopUsers[p.Namespace] = u.DesktopAccess
	}
	if c.Chrome != nil {
		for _, grant := range c.Chrome.Grants {
			scope, err := chrome.NormalizeTrustScope(grant.TrustScope)
			if err != nil {
				return err
			}
			if scope == chrome.TrustScopeDesktop && (c.Chrome.FixtureEnrollment || c.Chrome.ProcessTrust == nil || !desktopUsers[grant.Principal.Namespace]) {
				return errors.New("desktop-wide browser trust requires an explicitly enrolled desktop-wide user and production process verification")
			}
		}
	}
	return nil
}
