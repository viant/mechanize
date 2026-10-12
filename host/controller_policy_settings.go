package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"golang.org/x/sys/unix"
)

type controllerPolicySettings struct{ rootPath string }
type savedControllerPolicy struct {
	Version int                        `json:"version"`
	Key     chrome.ControllerPolicyKey `json:"key"`
	Policy  chrome.ControllerPolicy    `json:"policy"`
}

var errControllerSettings = errors.New("controller settings unavailable")

func controllerSettingsName(key chrome.ControllerPolicyKey) (string, error) {
	if key.Namespace == "" || key.ProfileChannel == "" || len(key.ProfileChannel) > 128 || key.BrowserInstance == "" || len(key.BrowserInstance) > 128 || key.ExtensionOrigin == "" {
		return "", errControllerSettings
	}
	raw, _ := json.Marshal(key)
	sum := sha256.Sum256(raw)
	return ".controller-policy-" + hex.EncodeToString(sum[:]) + ".json", nil
}
func readControllerPolicy(root *os.Root, key chrome.ControllerPolicyKey) (chrome.ControllerPolicy, error) {
	name, e := controllerSettingsName(key)
	if e != nil {
		return chrome.ControllerPolicy{}, e
	}
	f, e := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if os.IsNotExist(e) {
		return chrome.ControllerPolicy{Origins: []string{}}, nil
	}
	if e != nil {
		return chrome.ControllerPolicy{}, errControllerSettings
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !settingsFileSafe(info) || info.Size() > 16384 {
		return chrome.ControllerPolicy{}, errControllerSettings
	}
	raw, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil {
		return chrome.ControllerPolicy{}, errControllerSettings
	}
	// Closed decoding includes duplicate-key rejection, not just unknown keys.
	if !controllerSettingsUniqueJSON(raw) {
		return chrome.ControllerPolicy{}, errControllerSettings
	}
	var saved savedControllerPolicy
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&saved) != nil || decoder.Decode(new(any)) != io.EOF || saved.Version != 1 || saved.Key != key || !chrome.ValidControllerPolicy(saved.Policy) {
		return chrome.ControllerPolicy{}, errControllerSettings
	}
	return saved.Policy, nil
}
func controllerSettingsUniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 8 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		delimiter, ok := t.(json.Delim)
		if !ok {
			return true
		}
		if delimiter != '{' && delimiter != '[' {
			return false
		}
		seen := map[string]bool{}
		for d.More() {
			if delimiter == '{' {
				k, e := d.Token()
				name, ok := k.(string)
				name = strings.ToLower(name)
				if e != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
			}
			if !value(depth + 1) {
				return false
			}
		}
		close, e := d.Token()
		return e == nil && (delimiter == '{' && close == json.Delim('}') || delimiter == '[' && close == json.Delim(']'))
	}
	return value(0) && d.Decode(new(any)) == io.EOF
}
func (s *controllerPolicySettings) Load(key chrome.ControllerPolicyKey) (chrome.ControllerPolicy, error) {
	if !controllerSettingsOutsideGit(s.rootPath) {
		return chrome.ControllerPolicy{}, errControllerSettings
	}
	root, e := openSettingsRoot(s.rootPath)
	if e != nil {
		if os.IsNotExist(e) && controllerSettingsMissingRoot(s.rootPath) {
			if _, err := controllerSettingsName(key); err != nil {
				return chrome.ControllerPolicy{}, err
			}
			return chrome.ControllerPolicy{Origins: []string{}}, nil
		}
		return chrome.ControllerPolicy{}, errControllerSettings
	}
	defer root.Close()
	return readControllerPolicy(root, key)
}
func (s *controllerPolicySettings) Save(ctx context.Context, p auth.Principal, key chrome.ControllerPolicyKey, policy chrome.ControllerPolicy) error {
	actual, e := auth.FromContext(ctx)
	if e != nil || !auth.NativeHuman(ctx) || !p.HasScope("consent:admin") || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || key.Namespace != p.Namespace || ctx.Err() != nil {
		return auth.ErrUnauthorized
	}
	if !chrome.ValidControllerPolicy(policy) {
		return errControllerSettings
	}
	name, e := controllerSettingsName(key)
	if e != nil {
		return e
	}
	if !controllerSettingsOutsideGit(s.rootPath) {
		return errControllerSettings
	}
	root, e := openSettingsRoot(s.rootPath)
	if e != nil {
		return errControllerSettings
	}
	defer root.Close()
	lock, e := root.OpenFile(".controller-policy.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return errControllerSettings
	}
	defer lock.Close()
	info, e := lock.Stat()
	if e != nil || !settingsFileSafe(info) || unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errControllerSettings
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if _, e = readControllerPolicy(root, key); e != nil {
		return e
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return errControllerSettings
	}
	tmp := ".controller-policy-write-" + hex.EncodeToString(nonce)
	defer root.Remove(tmp)
	f, e := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return errControllerSettings
	}
	raw, _ := json.Marshal(savedControllerPolicy{Version: 1, Key: key, Policy: policy})
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	closeError := f.Close()
	if e != nil || closeError != nil || ctx.Err() != nil || root.Rename(tmp, name) != nil {
		return errControllerSettings
	}
	directory, e := root.Open(".")
	if e != nil {
		return errControllerSettings
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return errControllerSettings
	}
	return nil
}

func controllerSettingsOutsideGit(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	for current := path; ; current = filepath.Dir(current) {
		if _, e := os.Lstat(filepath.Join(current, ".git")); e == nil || !os.IsNotExist(e) {
			return false
		}
		if current == filepath.Dir(current) {
			return true
		}
	}
}

// Absence is a first-activation default only when every existing component is
// an actual directory. EvalSymlinks ENOENT alone also covers dangling links.
// This check does not create storage or grant controller access.
func controllerSettingsMissingRoot(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !controllerSettingsOutsideGit(path) {
		return false
	}
	current := string(filepath.Separator)
	missing := false
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			missing = true
			continue
		}
		if err != nil || missing || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return false
		}
	}
	return missing
}
