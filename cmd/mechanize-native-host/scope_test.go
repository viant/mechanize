package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
	"github.com/viant/scy"
)

func TestBrowserTrustScopeDefaultsStrictAndDesktopIsExplicit(t *testing.T) {
	for _, scope := range []string{"", "profile"} {
		config := &Config{TrustScope: scope, processQualified: true}
		if got, err := configuredTrustScope(config); err != nil || got != "profile" {
			t.Fatalf("legacy profile scope: %q %v", got, err)
		}
		if Bridge(nil, nil, nil, config, "credential") == nil {
			t.Fatal("strict profile bridge granted without reconnect profile proof")
		}
	}
	for _, config := range []*Config{{TrustScope: "all"}, {TrustScope: "Desktop"}, {TrustScope: "desktop", ProfileDirectory: "/enrolled/profile"}} {
		if _, err := configuredTrustScope(config); err == nil {
			t.Fatal("unknown or contradictory browser trust accepted")
		}
	}
	if scope, err := configuredTrustScope(&Config{TrustScope: "desktop"}); err != nil || scope != "desktop" {
		t.Fatal("explicit empty-profile desktop mode rejected")
	}
}

func TestPrivateConfigurationTrustScopeParsingIsClosed(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	origin := "chrome-extension://" + strings.Repeat("a", 32) + "/"
	config := Config{FixtureEnrollment: true, SocketPath: filepath.Join(dir, "broker.sock"), ExtensionOrigin: origin, ProfileChannel: "p", BrowserInstance: "b", CredentialResource: scy.Resource{URL: filepath.Join(dir, "encrypted.sec"), Key: "blowfish://env/FIXTURE"}}
	for _, scope := range []string{"", "profile", "desktop", "unknown"} {
		config.TrustScope = scope
		path := filepath.Join(dir, "config.json")
		body, _ := json.Marshal(config)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		loaded, err := loadConfig(path, origin)
		if scope == "unknown" {
			if err == nil {
				t.Fatal("unknown private trust scope accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		got, _ := configuredTrustScope(loaded)
		want := scope
		if want == "" {
			want = "profile"
		}
		if got != want || loaded.processQualified || loaded.profileQualified {
			t.Fatal("configuration minted process/profile proof")
		}
	}
}

func browserScopeEvidence() nativepeer.ChromeProcessEvidence {
	parent := session.ProcessIdentity{PID: 20}
	return nativepeer.ChromeProcessEvidence{NativeHost: session.ProcessIdentity{PID: 10}, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}}
}

func TestDesktopLaunchBypassesOnlyProfileAndStillRequiresImmediateParent(t *testing.T) {
	evidence := browserScopeEvidence()
	config := &Config{TrustScope: "desktop", ProcessTrust: &nativepeer.ChromeProcessPolicy{}, profileQualified: true}
	if err := qualifyLaunchScope(config, evidence, []string{"/host", "extension-origin"}); err != nil || config.profileQualified {
		t.Fatalf("desktop forged or required profile proof: %v", err)
	}
	for _, ancestors := range [][]session.ProcessIdentity{nil, {{PID: 99}, evidence.ChromeParent}, {{PID: 99}}} {
		changed := evidence
		changed.Ancestors = ancestors
		if qualifyLaunchScope(config, changed, nil) == nil {
			t.Fatal("desktop admitted intermediary or unproven parent")
		}
	}
	if Bridge(nil, nil, nil, &Config{TrustScope: "desktop"}, "credential") == nil {
		t.Fatal("desktop admitted without production process proof")
	}
}

func TestStrictLaunchRequiresActualReconnectNotSignedParentArguments(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(dir, "Default")
	if err := os.Mkdir(profile, 0700); err != nil {
		t.Fatal(err)
	}
	origin := "chrome-extension://" + strings.Repeat("a", 32) + "/"
	executable := "/enrolled/Chrome"
	config := &Config{ProfileDirectory: profile, ExtensionOrigin: origin, ProcessTrust: &nativepeer.ChromeProcessPolicy{ChromeExecutable: executable, ExpectedUID: uint32(os.Getuid())}}
	evidence := browserScopeEvidence()
	if qualifyLaunchScope(config, evidence, []string{"/host", origin}) == nil || config.profileQualified {
		t.Fatal("signed parent silently supplied profile launch proof")
	}
	command := []string{executable, "--no-startup-window", "--native-messaging-connect-host=com.viant.mechanize", "--native-messaging-connect-extension=" + strings.Repeat("a", 32), "--enable-features=OnConnectNative", "--profile-directory=Default", "--user-data-dir=" + dir}
	encoded, _ := json.Marshal(command)
	args := []string{"/host", origin, "--reconnect-command=" + base64.StdEncoding.EncodeToString(encoded)}
	if err := qualifyLaunchScope(config, evidence, args); err != nil || !config.profileQualified {
		t.Fatalf("actual strict reconnect rejected: %v", err)
	}
}

func readScopeHello(t *testing.T, config *Config) map[string]any {
	t.Helper()
	host, broker := net.Pipe()
	defer host.Close()
	defer broker.Close()
	var input bytes.Buffer
	_ = WriteFrame(&input, json.RawMessage(`{"type":"hello","protocolVersion":1,"profileChannel":"p","browserInstance":"b","trustScope":"desktop","profileDirectory":"/forged","profileLaunchQualified":true}`))
	done := make(chan error, 1)
	go func() { done <- Bridge(&input, io.Discard, host, config, "host-credential") }()
	frame, err := ReadFrame(broker)
	if err != nil {
		t.Fatal(err)
	}
	var hello map[string]any
	if err := json.Unmarshal(frame, &hello); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	return hello
}

func TestNativeHelloCannotWidenTrustAndDesktopNeverClaimsProfile(t *testing.T) {
	for _, test := range []struct {
		name, scope, path  string
		fixture, qualified bool
		want               string
	}{
		{"legacy caller cannot enable desktop", "", "/enrolled/profile", false, true, "profile"},
		{"configured desktop", "desktop", "", false, false, "desktop"},
		{"fixture cannot claim production profile", "profile", "/fixture/profile", true, true, "profile"},
		{"fixture desktop remains unqualified", "desktop", "", true, true, "desktop"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := &Config{TrustScope: test.scope, ProfileDirectory: test.path, FixtureEnrollment: test.fixture, processQualified: !test.fixture, profileQualified: test.qualified, ProfileChannel: "p", BrowserInstance: "b"}
			hello := readScopeHello(t, config)
			wantProfile := !test.fixture && test.want == "profile" && test.qualified
			if hello["trustScope"] != test.want || hello["profileDirectory"] != test.path || hello["profileLaunchQualified"] != wantProfile || hello["fixtureEnrollment"] != test.fixture {
				t.Fatal("caller forged configured trust or profile proof")
			}
		})
	}
}

func TestDesktopCredentialsStillRequireReversePeerBeforeScy(t *testing.T) {
	setEmbeddedBrokerFixture(t, "signed-broker-pin")
	for _, peerRejected := range []bool{true, false} {
		steps := []string{}
		config := &Config{TrustScope: "desktop", BrokerRequirement: "signed-broker-pin"}
		value, err := authenticatedCredential(context.Background(), config, nil, func(context.Context, *Config) (nativepeer.ChromeProcessEvidence, error) {
			steps = append(steps, "process")
			return browserScopeEvidence(), nil
		}, func(*Config, net.Conn) error {
			steps = append(steps, "peer")
			if peerRejected {
				return errors.New("untrusted reverse peer")
			}
			return nil
		}, func() (string, error) { steps = append(steps, "Scy"); return "fixture-credential", nil })
		if peerRejected {
			if err == nil || value != "" || !reflect.DeepEqual(steps, []string{"process", "peer"}) || config.processQualified {
				t.Fatal("desktop read credentials before reverse peer proof")
			}
		} else if err != nil || !reflect.DeepEqual(steps, []string{"process", "peer", "Scy", "peer", "process"}) || !config.processQualified || config.profileQualified {
			t.Fatal("desktop credential order or proof dishonest")
		}
	}
}
