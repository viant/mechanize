package host

import (
	"github.com/viant/mechanize/auth"
	"os"
	"path/filepath"
	"testing"
)

func TestConsoleOwnedTransportRequiresFixedAppAndHelperPrivacyGuard(t *testing.T) {
	home, _ := os.UserHomeDir()
	uid := uint32(os.Getuid())
	base := Config{IdentityPolicy: auth.Policy{Issuer: "fixture", Audience: "fixture", Algorithms: []string{"HS256"}}, Users: []User{{Subject: "owner", DesktopAccess: true}}, SourceRoot: "/fixture/source", StorageRoot: "/fixture/storage", NativeHelper: filepath.Join(home, "Applications/Mechanize.app/Contents/Helpers/mechanize-native"), NativeConsole: &NativeConsoleConfig{SocketPath: filepath.Join(home, "Library/Application Support/Mechanize/runtime/consent.sock"), ExpectedUID: uid, DesignatedRequirement: "console-pin"}, NativeLaunch: &NativeLaunchConfig{Transport: "console-v1", LockPath: "/fixture/fence", HelperRequirement: "helper-pin", ExpectedUID: &uid}}
	if e := base.Validate(); e != nil {
		t.Fatal(e)
	}
	route := base.consoleHelperLaunch()
	if route == nil || route.SocketPath != base.NativeConsole.SocketPath+".helper" || route.Requirement != "console-pin" {
		t.Fatal("launcher enrollment differs")
	}
	options, e := launchHostOptions(base)
	if e != nil || options.NativeControl.ConsoleLaunch == nil || *options.NativeControl.ConsoleLaunch != *route {
		t.Fatal("control helper lost console route")
	}
	for _, which := range []string{"unknown", "endpoint", "helper", "guard"} {
		t.Run(which, func(t *testing.T) {
			c := base
			l := *base.NativeLaunch
			c.NativeLaunch = &l
			n := *base.NativeConsole
			c.NativeConsole = &n
			switch which {
			case "unknown":
				l.Transport = "automatic"
			case "endpoint":
				n.SocketPath = "/fixture/untrusted.sock"
			case "helper":
				c.NativeHelper = "/fixture/helper"
			case "guard":
				c.NativeVault = &NativeVaultConfig{WindowProtection: ""}
			}
			if c.Validate() == nil {
				t.Fatal("invalid console route admitted")
			}
		})
	}
	legacy := base
	l := *base.NativeLaunch
	l.Transport = ""
	legacy.NativeLaunch = &l
	if legacy.consoleHelperLaunch() != nil {
		t.Fatal("legacy transport silently changed")
	}
}
