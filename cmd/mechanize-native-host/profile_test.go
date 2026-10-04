package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChromeReconnectProfileIsBoundedDataAndExactScope(t *testing.T) {
	origin := "chrome-extension://" + strings.Repeat("a", 32) + "/"
	executable := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	command := []string{executable, "--no-startup-window", "--native-messaging-connect-host=com.viant.mechanize", "--native-messaging-connect-extension=" + strings.Repeat("a", 32), "--enable-features=OnConnectNative", "--profile-directory=Default", "--user-data-dir=/private/tmp/disposable"}
	encode := func(value []string) []string {
		raw, _ := json.Marshal(value)
		return []string{"/host", origin, "--reconnect-command=" + base64.StdEncoding.EncodeToString(raw)}
	}
	if path, err := launchProfile(encode(command), executable, origin); err != nil || path != "/private/tmp/disposable/Default" {
		t.Fatalf("valid reconnect: %q %v", path, err)
	}
	cases := map[string][]string{"missing": command[:6], "duplicate": append(append([]string{}, command...), command[6])}
	for name, replacement := range map[string]string{"executable": "/evil", "host": "--native-messaging-connect-host=evil", "origin": "--native-messaging-connect-extension=" + strings.Repeat("b", 32), "feature": "--enable-features=Other", "traversal": "--profile-directory=../Other", "relative": "--user-data-dir=relative"} {
		copyCommand := append([]string{}, command...)
		index := map[string]int{"executable": 0, "host": 2, "origin": 3, "feature": 4, "traversal": 5, "relative": 6}[name]
		copyCommand[index] = replacement
		cases[name] = copyCommand
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := launchProfile(encode(value), executable, origin); err == nil {
				t.Fatal("unsafe reconnect accepted")
			}
		})
	}
	for _, args := range [][]string{{"/host", origin}, {"/host", origin, "--reconnect-command=!!!"}, {"/host", origin, "--reconnect-command=" + strings.Repeat("a", 16385)}, append(encode(command), "--reconnect-command=duplicate")} {
		if _, err := launchProfile(args, executable, origin); err == nil {
			t.Fatal("ambiguous launch accepted")
		}
	}
}
func TestChromeProfilePinRejectsAliasAndWritableDirectory(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = validateProfileDirectory(dir, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err = os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if validateProfileDirectory(alias, uint32(os.Getuid())) == nil {
		t.Fatal("alias accepted")
	}
	if err = os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if validateProfileDirectory(dir, uint32(os.Getuid())) == nil {
		t.Fatal("writable profile accepted")
	}
}

func TestChromeLaunchProfileErrorsWithholdReconnectPayload(t *testing.T) {
	origin := "chrome-extension://" + strings.Repeat("a", 32) + "/"
	secret := "fixture-private-reconnect-payload"
	for _, raw := range []string{secret, `["` + secret + `"]`, `["` + secret + `","1","2","3","4","5","6"]`} {
		encoded := base64.StdEncoding.EncodeToString([]byte(raw))
		_, err := launchProfile([]string{"/host", origin, "--reconnect-command=" + encoded}, "/enrolled/Chrome", origin)
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), encoded) {
			t.Fatalf("profile diagnostic accepted or disclosed input: %v", err)
		}
	}
}
