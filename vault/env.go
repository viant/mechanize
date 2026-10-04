package vault

import (
	"context"
	"encoding/base64"
	"github.com/viant/scy/kms"
	"regexp"
)

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// ScyEnvKeys is an explicit operator-configured alternative to Keychain. Scy's
// kms.Key.Key resolves env values; only enrolled version/name pairs are accepted.
// A master key is 32 random bytes, represented as 32 raw bytes or base64. The
// environment locator (never its value) is trusted host configuration only.
// Host activation must strip these variables from every child process environment.
type ScyEnvKeys struct{ versions map[string]string }

func NewScyEnvKeys(versions map[string]string) (*ScyEnvKeys, error) {
	if len(versions) == 0 {
		return nil, ErrUnavailable
	}
	r := &ScyEnvKeys{versions: map[string]string{}}
	for version, name := range versions {
		if version == "" || len(version) > 128 || !envName.MatchString(name) {
			return nil, ErrUnavailable
		}
		r.versions[version] = name
	}
	return r, nil
}
func (r *ScyEnvKeys) Resolve(ctx context.Context, version string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, ok := r.versions[version]
	if !ok {
		return nil, ErrUnavailable
	}
	b, err := (&kms.Key{Kind: "env", Path: name}).Key(ctx, nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	if len(b) == 32 {
		return b, nil
	}
	defer clear(b)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(decoded, b)
	if err != nil || n != 32 {
		clear(decoded)
		return nil, ErrUnavailable
	}
	return decoded[:n], nil
}

// ChildEnvironment creates an environment with enrolled master-key variables
// removed. It must be applied by every shell/helper/browser subprocess launcher
// before enabling env-key mode; this package does not activate process execution.
func (r *ScyEnvKeys) ChildEnvironment(inherited []string) []string {
	blocked := map[string]bool{}
	for _, name := range r.versions {
		blocked[name] = true
	}
	result := make([]string, 0, len(inherited))
	for _, item := range inherited {
		name := item
		for i, c := range item {
			if c == '=' {
				name = item[:i]
				break
			}
		}
		if !blocked[name] {
			result = append(result, item)
		}
	}
	return result
}
