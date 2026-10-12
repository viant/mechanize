package host

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/viant/mechanize/security/keychain"
	"github.com/viant/mechanize/vault"
)

func nativeVaultConfigFixture(t *testing.T) Config {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	return Config{NativeConsole: &NativeConsoleConfig{SocketPath: "/fixture/console.sock", DesignatedRequirement: `identifier "com.viant.mechanize.consent"`, ExpectedUID: uint32(os.Getuid())}, Keychain: &keychain.Options{Items: map[string]keychain.Item{"vault-master-v1": {Service: "com.viant.mechanize.vault", Account: "fixture-operator-v1"}}}, NativeVault: &NativeVaultConfig{Root: filepath.Join(home, ".secret", "vault"), KeyAlias: "vault-master-v1", KeyVersion: "vault-v1", BrokerRequirement: `identifier "com.viant.mechanize"`}}
}
func TestNativeVaultConfigurationRefusesSourcePathsAndUnenrolledKeys(t *testing.T) {
	if err := nativeVaultConfigFixture(t).validateNativeVault(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"source-root", "relative-root", "alternative-root", "console", "foreign-uid", "keychain", "missing-alias", "invalid-alias", "console-item", "empty-account", "empty-version", "invalid-version", "missing-broker", "foreign-broker"} {
		t.Run(mode, func(t *testing.T) {
			c := nativeVaultConfigFixture(t)
			switch mode {
			case "source-root":
				c.NativeVault.Root = "/fixture/source/vault"
			case "relative-root":
				c.NativeVault.Root = ".secret/vault"
			case "alternative-root":
				c.NativeVault.Root = filepath.Dir(c.NativeVault.Root)
			case "console":
				c.NativeConsole = nil
			case "foreign-uid":
				c.NativeConsole.ExpectedUID++
			case "keychain":
				c.Keychain = nil
			case "missing-alias":
				c.NativeVault.KeyAlias = "not-enrolled"
			case "invalid-alias":
				c.NativeVault.KeyAlias = "../vault"
			case "console-item":
				c.Keychain.Items[c.NativeVault.KeyAlias] = keychain.Item{Service: "com.viant.mechanize.console.enrollment", Account: "fixture"}
			case "empty-account":
				c.Keychain.Items[c.NativeVault.KeyAlias] = keychain.Item{Service: "com.viant.mechanize.vault"}
			case "empty-version":
				c.NativeVault.KeyVersion = ""
			case "invalid-version":
				c.NativeVault.KeyVersion = "inline/key"
			case "missing-broker":
				c.NativeVault.BrokerRequirement = ""
			case "foreign-broker":
				c.ChromeRetirement = &ChromeRetirementConfig{BrokerRequirement: `identifier "other"`}
			}
			if err := c.validateNativeVault(); err == nil {
				t.Fatal("unsafe native Vault enrollment accepted")
			}
		})
	}
}
func TestNativeVaultConfigurationCannotMixInjectedProviders(t *testing.T) {
	h, err := NewWithOptions(context.Background(), nativeVaultConfigFixture(t), HostOptions{NativeVaultInput: &vault.NativeInputService{}})
	if h != nil || err == nil || !strings.Contains(err.Error(), "cannot mix") {
		t.Fatal("injected Vault provider overrode configured custody")
	}
}
func TestNativeVaultDecodeRejectsInlineKeyOrCredentialFields(t *testing.T) {
	for _, field := range []string{"key", "password", "username", "keyMaterial", "fallback"} {
		if _, err := DecodeConfig(strings.NewReader(`{"nativeVault":{"` + field + `":"synthetic-canary"}}`)); err == nil {
			t.Fatal("secret-bearing native Vault configuration accepted")
		}
	}
}

func TestNativeRecordConfigurationSelectsOnlySeparatePrivateRoot(t *testing.T) {
	c := nativeVaultConfigFixture(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	c.NativeVault.RecordRoot = filepath.Join(home, ".secret", "vault-records")
	if err := c.validateNativeVault(); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{c.NativeVault.Root, c.NativeVault.Root + "/records", "/fixture/source/records", ".secret/vault-records", c.NativeVault.RecordRoot + "/../vault-records"} {
		c.NativeVault.RecordRoot = root
		if c.validateNativeVault() == nil {
			t.Fatal("unsafe or overlapping generic record root accepted")
		}
	}
}

func TestNativeRecordsCannotOverrideConfigurationOrOmitCustody(t *testing.T) {
	provider := &vault.NativeRecordInputService{}
	h, err := NewWithOptions(context.Background(), nativeVaultConfigFixture(t), HostOptions{NativeVaultRecords: provider})
	if h != nil || err == nil || !strings.Contains(err.Error(), "cannot mix") {
		t.Fatal("injected records overrode configured providers")
	}
	h, err = NewWithOptions(context.Background(), Config{}, HostOptions{NativeVaultRecords: provider})
	if h != nil || err == nil || !strings.Contains(err.Error(), "matching signed lifecycle") {
		t.Fatal("generic records accepted without protected multi-store custody")
	}
}

func TestNativeVaultScyLocalConfigurationDoesNotRequireKeychain(t *testing.T) {
	c := nativeVaultConfigFixture(t)
	c.NativeVault.KeyProvider = "scy-local-v1"
	c.Keychain = nil
	if e := c.validateNativeVault(); e != nil {
		t.Fatal("local Scy custody still requires Keychain enrollment")
	}
	c.NativeVault.KeyProvider = "keychain-v1"
	if e := c.validateNativeVault(); e == nil {
		t.Fatal("legacy provider lost its enrollment requirement")
	}
	c.NativeVault.KeyProvider = "unconfigured-provider"
	if e := c.validateNativeVault(); e == nil {
		t.Fatal("unconfigured provider admitted")
	}
}
