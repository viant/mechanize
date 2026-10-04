package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
)

func TestProductionCredentialRequiresBothProcessAndReversePeerProofFirst(t *testing.T) {
	setEmbeddedBrokerFixture(t, "fixture-broker-pin")
	config := &Config{BrokerRequirement: "fixture-broker-pin"}
	for _, failure := range []string{"process", "peer", "none"} {
		t.Run(failure, func(t *testing.T) {
			steps := []string{}
			loads := 0
			value, err := authenticatedCredential(context.Background(), config, nil, func(context.Context, *Config) (nativepeer.ChromeProcessEvidence, error) {
				steps = append(steps, "process")
				if failure == "process" {
					return nativepeer.ChromeProcessEvidence{}, errors.New("untrusted ancestry")
				}
				return nativepeer.ChromeProcessEvidence{NativeHost: session.ProcessIdentity{PID: 10}, ChromeParent: session.ProcessIdentity{PID: 20}}, nil
			}, func(*Config, net.Conn) error {
				steps = append(steps, "peer")
				if failure == "peer" {
					return errors.New("untrusted broker")
				}
				return nil
			}, func() (string, error) { steps = append(steps, "load"); loads++; return "private-fixture-value", nil })
			if failure != "none" {
				if err == nil || loads != 0 || value != "" {
					t.Fatal("credential loaded before trusted process/channel proof")
				}
			} else {
				if err != nil || loads != 1 || !reflect.DeepEqual(steps, []string{"process", "peer", "load", "peer", "process"}) {
					t.Fatalf("authentication order: %v %v", steps, err)
				}
			}
		})
	}
}
func TestProductionCredentialDoesNotReturnSecretAfterPeerOrParentChanges(t *testing.T) {
	setEmbeddedBrokerFixture(t, "fixture-broker-pin")
	for _, changed := range []string{"peer", "parent"} {
		t.Run(changed, func(t *testing.T) {
			checks := 0
			peerChecks := 0
			value, err := authenticatedCredential(context.Background(), &Config{BrokerRequirement: "fixture-broker-pin"}, nil, func(context.Context, *Config) (nativepeer.ChromeProcessEvidence, error) {
				checks++
				pid := 20
				if checks > 1 && changed == "parent" {
					pid = 21
				}
				return nativepeer.ChromeProcessEvidence{NativeHost: session.ProcessIdentity{PID: 10}, ChromeParent: session.ProcessIdentity{PID: pid}}, nil
			}, func(*Config, net.Conn) error {
				peerChecks++
				if peerChecks > 1 && changed == "peer" {
					return errors.New("peer changed")
				}
				return nil
			}, func() (string, error) { return "private-fixture-value", nil })
			if err == nil || value != "" {
				t.Fatal("credential exposed after channel identity changed")
			}
		})
	}
}
func TestPrivateConfigurationOwnershipLinksModesAndProductionBridgeGate(t *testing.T) {
	dir := t.TempDir()
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(canonical, "config.json")
	if err = os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = validatePrivateFile(path); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(canonical, "alias.json")
	if err = os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if validatePrivateFile(alias) == nil {
		t.Fatal("configuration symlink accepted")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if validatePrivateFile(path) == nil {
		t.Fatal("nonprivate configuration accepted")
	}
	if err = Bridge(nil, nil, nil, &Config{}, "not-loaded"); err == nil {
		t.Fatal("production bridge without signed channel admission")
	}
}

// These tests are deliberately nonparallel: the builder-populated variable is
// changed only inside one bounded fixture and restored before the next test.
func setEmbeddedBrokerFixture(t *testing.T, pin string) {
	t.Helper()
	previous := embeddedBrokerRequirement
	embeddedBrokerRequirement = pin
	t.Cleanup(func() { embeddedBrokerRequirement = previous })
}
func TestSignedImageBrokerPinMissingOrMismatchCannotLoadCredential(t *testing.T) {
	for _, test := range []struct{ name, pin, configured string }{
		{"missing image pin", "", "configured pin"},
		{"configuration differs", "embedded exact pin", "substituted pin"},
		{"empty configuration", "embedded exact pin", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			setEmbeddedBrokerFixture(t, test.pin)
			value, err := authenticatedCredential(context.Background(), &Config{BrokerRequirement: test.configured}, nil,
				func(context.Context, *Config) (nativepeer.ChromeProcessEvidence, error) {
					t.Error("Unpinned config reached process verification")
					return nativepeer.ChromeProcessEvidence{}, nil
				},
				func(*Config, net.Conn) error { t.Error("Unpinned config reached broker verification"); return nil },
				func() (string, error) {
					t.Error("Unpinned config loaded credentials")
					return "private-fixture-value", nil
				})
			if err == nil || value != "" {
				t.Fatal("missing/mismatched signed-image broker pin admitted")
			}
		})
	}
}
func TestFixturePathDoesNotRequireCompiledProductionPin(t *testing.T) {
	setEmbeddedBrokerFixture(t, "")
	if err := validateEmbeddedBrokerRequirement(&Config{FixtureEnrollment: true}); err != nil {
		t.Fatal(err)
	}
}
