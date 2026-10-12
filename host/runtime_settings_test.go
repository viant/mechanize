package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/viant/mechanize/auth"
)

func settingsFixture(t *testing.T) *Host {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return &Host{runtimeSettingsRoot: root, runtimeListen: "127.0.0.1:4987"}
}
func TestRuntimePortSaveAppliesOnlyAtNextHTTPStartupAndPreservesStdio(t *testing.T) {
	h := settingsFixture(t)
	before, err := h.runtimeSettings()
	if err != nil || before.CurrentPort != 4987 || before.Revision != 0 || before.RestartRequired {
		t.Fatal("invalid initial settings")
	}
	saved, err := h.saveRuntimePort(0, 5100)
	if err != nil || saved.CurrentPort != 4987 || saved.SavedPort != 5100 || saved.Revision != 1 || !saved.RestartRequired {
		t.Fatal("save changed active endpoint or lost restart state")
	}
	if _, err = h.saveRuntimePort(0, 5200); !errors.Is(err, errRuntimeSettings) {
		t.Fatal("stale settings overwrote pending port")
	}
	address, err := LoadRuntimeListen(h.runtimeSettingsRoot, h.runtimeListen)
	if err != nil || address != "127.0.0.1:5100" {
		t.Fatal("restart did not select saved port")
	}
	if address, err = LoadRuntimeListen(h.runtimeSettingsRoot, ""); err != nil || address != "" {
		t.Fatal("port override changed stdio transport")
	}
	for _, bad := range []string{"0.0.0.0:5100", "example.test:5100", "192.168.0.1:5100", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:05100"} {
		if _, err = LoadRuntimeListen(h.runtimeSettingsRoot, bad); err == nil {
			t.Fatal("invalid/remote endpoint allowed")
		}
	}
}
func TestRuntimePortRefusesUnsafeFilesAndInvalidValues(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "public-file", "malformed", "extra-field"} {
		t.Run(mode, func(t *testing.T) {
			h := settingsFixture(t)
			path := filepath.Join(h.runtimeSettingsRoot, ".mcp-port.json")
			data := []byte(`{"port":5100,"revision":1}`)
			if mode == "malformed" {
				data = []byte(`{"port":0,"revision":1}`)
			}
			if mode == "extra-field" {
				data = []byte(`{"port":5100,"revision":1,"password":"synthetic-canary"}`)
			}
			if mode == "symlink" || mode == "hardlink" {
				other := filepath.Join(h.runtimeSettingsRoot, "other")
				os.WriteFile(other, data, 0600)
				if mode == "symlink" {
					os.Symlink(other, path)
				} else {
					os.Link(other, path)
				}
			} else {
				os.WriteFile(path, data, 0600)
				if mode == "public-file" {
					os.Chmod(path, 0644)
				}
			}
			if _, err := h.runtimeSettings(); err == nil {
				t.Fatal("unsafe settings read")
			}
			if _, err := h.saveRuntimePort(1, 5200); err == nil {
				t.Fatal("unsafe settings overwritten")
			}
		})
	}
	h := settingsFixture(t)
	for _, port := range []int{0, -1, 65536} {
		if _, err := h.saveRuntimePort(0, port); err == nil {
			t.Fatal("invalid port saved")
		}
	}
}
func TestRuntimeSettingsRequireNativeEnrolledAuthority(t *testing.T) {
	h := settingsFixture(t)
	p, _ := auth.NewPrincipal("fixture", "", "settings-owner", []string{"consent:admin"})
	h.users = map[string]User{p.Namespace: {Subject: p.Subject}}
	ctx := auth.WithPrincipal(context.Background(), p)
	if _, err := h.NativeInformation(ctx, "settings.get", nil); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("agent read native settings")
	}
	human, _ := auth.WithNativeHuman(ctx)
	if _, err := h.NativeInformation(human, "settings.get", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.NativeInformation(human, "settings.port.set", []byte(`{"sessionID":"fixture","expectedRevision":0,"port":5100,"host":"0.0.0.0"}`)); err == nil {
		t.Fatal("caller selected listener host")
	}
	delete(h.users, p.Namespace)
	if _, err := h.NativeInformation(human, "settings.get", nil); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("unenrolled subject read settings")
	}
}
