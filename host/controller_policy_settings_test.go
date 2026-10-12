package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
)

func controllerSettingsFixture(t *testing.T) (*controllerPolicySettings, context.Context, auth.Principal, chrome.ControllerPolicyKey) {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	p, _ := auth.NewPrincipal("fixture", "", "controller-owner", []string{"consent:admin", "desktop:control"})
	p.ClientID = "native-console"
	human, _ := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
	return &controllerPolicySettings{rootPath: root}, human, p, chrome.ControllerPolicyKey{Namespace: p.Namespace, ProfileChannel: "profile", BrowserInstance: "browser", ExtensionOrigin: "chrome-extension://fixture"}
}
func TestControllerPolicySettingsRestartAndExactEnrollmentIsolation(t *testing.T) {
	s, ctx, p, key := controllerSettingsFixture(t)
	policy := chrome.ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test", "http://localhost:3000"}}
	if e := s.Save(ctx, p, key, policy); e != nil {
		t.Fatal(e)
	}
	restarted := &controllerPolicySettings{rootPath: s.rootPath}
	saved, e := restarted.Load(key)
	if e != nil || !saved.Enabled || len(saved.Origins) != 2 {
		t.Fatal("policy did not survive restart", e)
	}
	for _, field := range []string{"namespace", "profile", "browser", "extension"} {
		changed := key
		switch field {
		case "namespace":
			changed.Namespace = "foreign"
		case "profile":
			changed.ProfileChannel = "other"
		case "browser":
			changed.BrowserInstance = "other"
		default:
			changed.ExtensionOrigin = "chrome-extension://other"
		}
		loaded, e := restarted.Load(changed)
		if e != nil || loaded.Enabled || len(loaded.Origins) != 0 {
			t.Fatal("settings crossed enrollment", field, e)
		}
	}
	policy.Enabled = false
	if e = s.Save(ctx, p, key, policy); e != nil {
		t.Fatal(e)
	}
	saved, e = restarted.Load(key)
	if e != nil || saved.Enabled {
		t.Fatal("disabled policy not persisted")
	}
}
func TestControllerPolicySettingsUnauthorizedSaveDoesNotCreateFile(t *testing.T) {
	s, human, p, key := controllerSettingsFixture(t)
	agent := auth.WithPrincipal(context.Background(), p)
	foreign := key
	foreign.Namespace = "foreign"
	policy := chrome.ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test"}}
	if e := s.Save(agent, p, key, policy); !errors.Is(e, auth.ErrUnauthorized) {
		t.Fatal("agent saved native policy")
	}
	if e := s.Save(human, p, foreign, policy); !errors.Is(e, auth.ErrUnauthorized) {
		t.Fatal("foreign namespace save")
	}
	entries, e := os.ReadDir(s.rootPath)
	if e != nil || len(entries) != 0 {
		t.Fatal("unauthorized save wrote files")
	}
}
func TestControllerPolicySettingsCorruptionAndUnsafeCustodyFailClosed(t *testing.T) {
	for _, mode := range []string{"malformed", "extra", "duplicate", "wrongKey", "invalidOrigin", "public", "hardlink", "symlink", "publicRoot", "symlinkRoot", "gitRoot"} {
		t.Run(mode, func(t *testing.T) {
			s, ctx, p, key := controllerSettingsFixture(t)
			policy := chrome.ControllerPolicy{Enabled: true, Origins: []string{"https://shell.fixture.test"}}
			if e := s.Save(ctx, p, key, policy); e != nil {
				t.Fatal(e)
			}
			name, _ := controllerSettingsName(key)
			path := filepath.Join(s.rootPath, name)
			switch mode {
			case "public":
				os.Chmod(path, 0644)
			case "publicRoot":
				os.Chmod(s.rootPath, 0755)
			case "gitRoot":
				if e := os.Mkdir(filepath.Join(s.rootPath, ".git"), 0700); e != nil {
					t.Fatal(e)
				}
			case "symlinkRoot":
				link := s.rootPath + "-link"
				if e := os.Symlink(s.rootPath, link); e != nil {
					t.Fatal(e)
				}
				defer os.Remove(link)
				s.rootPath = link
			case "hardlink":
				if e := os.Link(path, filepath.Join(s.rootPath, "linked")); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				old := path + "-real"
				os.Rename(path, old)
				os.Symlink(old, path)
			default:
				raw, _ := json.Marshal(savedControllerPolicy{Version: 1, Key: key, Policy: policy})
				if mode == "malformed" {
					raw = []byte("{")
				}
				if mode == "duplicate" {
					raw = append([]byte(`{"version":1,"version":1,`), raw[1:]...)
				}
				if mode == "extra" {
					raw = append([]byte(`{"sessionApproval":true,`), raw[1:]...)
				}
				if mode == "wrongKey" {
					bad := key
					bad.ProfileChannel = "foreign"
					raw, _ = json.Marshal(savedControllerPolicy{Version: 1, Key: bad, Policy: policy})
				}
				if mode == "invalidOrigin" {
					policy.Origins = []string{"https://shell.fixture.test/path"}
					raw, _ = json.Marshal(savedControllerPolicy{Version: 1, Key: key, Policy: policy})
				}
				os.WriteFile(path, raw, 0600)
			}
			loaded, e := s.Load(key)
			if e == nil || loaded.Enabled {
				t.Fatal("unsafe policy restored", mode)
			}
			if e = s.Save(ctx, p, key, chrome.ControllerPolicy{Enabled: false, Origins: []string{}}); e == nil {
				t.Fatal("unsafe file overwritten", mode)
			}
		})
	}
}

func TestControllerPolicyFirstActivationMissingRootIsDisabledWithoutCreatingStorage(t *testing.T) {
	s, _, _, key := controllerSettingsFixture(t)
	parent := s.rootPath
	s.rootPath = filepath.Join(parent, "not-yet-created", "runtime")
	policy, err := s.Load(key)
	if err != nil || policy.Enabled || len(policy.Origins) != 0 {
		t.Fatal("first activation failed or enabled access", err)
	}
	if _, err = os.Lstat(filepath.Join(parent, "not-yet-created")); !os.IsNotExist(err) {
		t.Fatal("read created runtime storage")
	}
	for _, mode := range []string{"danglingRoot", "symlinkParent", "unclean", "relative", "gitParent", "nonDirectoryParent"} {
		t.Run(mode, func(t *testing.T) {
			local, _, _, k := controllerSettingsFixture(t)
			switch mode {
			case "danglingRoot":
				link := filepath.Join(local.rootPath, "link")
				os.Symlink(filepath.Join(local.rootPath, "absent"), link)
				local.rootPath = link
			case "symlinkParent":
				real := filepath.Join(local.rootPath, "real")
				os.Mkdir(real, 0700)
				link := filepath.Join(local.rootPath, "link")
				os.Symlink(real, link)
				local.rootPath = filepath.Join(link, "absent")
			case "unclean":
				local.rootPath = local.rootPath + "/absent/../runtime"
			case "relative":
				local.rootPath = "absent-runtime"
			case "gitParent":
				os.Mkdir(filepath.Join(local.rootPath, ".git"), 0700)
				local.rootPath = filepath.Join(local.rootPath, "absent")
			case "nonDirectoryParent":
				file := filepath.Join(local.rootPath, "file")
				os.WriteFile(file, []byte("fixture"), 0600)
				local.rootPath = filepath.Join(file, "absent")
			}
			if policy, err := local.Load(k); err == nil || policy.Enabled {
				t.Fatal("unsafe missing root accepted", mode)
			}
		})
	}
}
