package host

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/viant/mechanize/artifact"
	"github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/security/keychain"
	"github.com/viant/mechanize/vault"
	"github.com/viant/scy"
)

// NativeVaultConfig contains routing/enrollment only. No inline keys, password
// fields, fallback resources or caller-selected Keychain item are accepted.
type NativeVaultConfig struct {
	KeyProvider       string `json:"keyProvider,omitempty"`
	WindowProtection  string `json:"windowProtection,omitempty"`
	Root              string `json:"root"`
	RecordRoot        string `json:"recordRoot,omitempty"`
	KeyVersion        string `json:"keyVersion"`
	KeyAlias          string `json:"keyAlias"`
	BrokerRequirement string `json:"brokerRequirement"`
}

func (c Config) validateNativeVault() error {
	v := c.NativeVault
	if v == nil {
		return nil
	}
	if v.KeyProvider != "" && v.KeyProvider != "keychain-v1" && v.KeyProvider != "scy-local-v1" {
		return errors.New("unsupported native Vault key provider")
	}
	if v.WindowProtection != "" && v.WindowProtection != "helper-v1" {
		return errors.New("unsupported native window protection")
	}
	if v.WindowProtection == "helper-v1" && (c.NativeHelper == "" || c.NativeLaunch == nil || c.NativeLaunch.HelperRequirement == "" || c.NativeLaunch.ExpectedUID == nil || *c.NativeLaunch.ExpectedUID != uint32(os.Getuid())) {
		return errors.New("private helper protection requires explicit native enrollment")
	}
	home, err := os.UserHomeDir()
	if err != nil || v.Root != filepath.Join(home, ".secret", "vault") || !filepath.IsAbs(v.Root) || filepath.Clean(v.Root) != v.Root {
		return errors.New("native Vault requires the private ~/.secret/vault location")
	}
	if v.RecordRoot != "" && v.RecordRoot != filepath.Join(home, ".secret", "vault-records") {
		return errors.New("native records require the separate private ~/.secret/vault-records location")
	}
	if c.NativeConsole == nil || c.NativeConsole.ExpectedUID != uint32(os.Getuid()) || v.KeyVersion == "" || len(v.KeyVersion) > 128 || strings.TrimSpace(v.BrokerRequirement) == "" || strings.ContainsRune(v.BrokerRequirement, 0) {
		return errors.New("native Vault requires console, local UID, key version and broker enrollment")
	}
	if _, err = keychain.Reference(v.KeyAlias); err != nil {
		return errors.New("native Vault requires an enrolled key alias")
	}
	if _, err = keychain.Reference(v.KeyVersion); err != nil {
		return errors.New("native Vault requires a bounded opaque key version")
	}
	if v.KeyProvider != "scy-local-v1" {
		if c.Keychain == nil {
			return errors.New("native Vault Keychain provider requires enrollment")
		}
		item, ok := c.Keychain.Items[v.KeyAlias]
		if !ok || item.Service != "com.viant.mechanize.vault" || strings.TrimSpace(item.Account) == "" || strings.ContainsRune(item.Account, 0) {
			return errors.New("native Vault key alias must select its own enrolled Keychain item")
		}
	}
	if c.ChromeRetirement != nil && c.ChromeRetirement.BrokerRequirement != v.BrokerRequirement {
		return errors.New("native Vault broker identity differs from the enrolled runtime")
	}
	return nil
}

type nativeVaultRuntime struct {
	store       *vault.Store
	input       *vault.NativeInputService
	entry       *vault.NativeEntryController
	setup       *vault.NativeKeySetup
	recordStore *vault.RecordStore
	records     *vault.NativeRecordInputService
}

// Called only after Config.Validate and Keychain provider registration. This
// opens the encrypted root but neither generates a key nor reads credentials.
func configuredNativeVault(c Config) (*nativeVaultRuntime, error) {
	if c.NativeVault == nil {
		return nil, nil
	}
	v := c.NativeVault
	var keys artifact.KeyResolver
	var local *vault.LocalKeyProvisioner
	var err error
	if v.KeyProvider == "scy-local-v1" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return nil, homeErr
		}
		local, err = vault.NewLocalKeyProvisioner(filepath.Join(home, ".secret", "vault-keys"), v.KeyAlias, v.KeyVersion)
		keys = local
	} else {
		ref, refErr := keychain.Reference(v.KeyAlias)
		if refErr != nil {
			return nil, refErr
		}
		resource := scy.NewResource("", ref, "")
		keys, err = artifact.NewScyResolver(map[string]scy.Resource{v.KeyVersion: *resource})
	}
	if err != nil {
		return nil, err
	}
	cipher := &vault.Cipher{Keys: keys}
	store, err := vault.NewStore(v.Root, v.KeyVersion, cipher)
	if err != nil {
		return nil, err
	}
	var recordStore *vault.RecordStore
	fail := func(err error) (*nativeVaultRuntime, error) {
		if recordStore != nil {
			_ = recordStore.Close()
		}
		_ = store.Close()
		return nil, err
	}
	var privateHelper *darwin.PrivateAdministration
	if v.WindowProtection == "helper-v1" {
		privateHelper, err = darwin.NewPrivateAdministration(darwin.Options{Console: c.consoleHelperLaunch(), HelperPath: c.NativeHelper, Requirement: c.NativeLaunch.HelperRequirement, ExpectedUID: c.NativeLaunch.ExpectedUID})
		if err != nil {
			return fail(err)
		}
	}
	gate, entry, err := vault.NewNativeWindowProtection(vault.NativeWindowOptions{ExpectedUID: c.NativeConsole.ExpectedUID, ConsoleRequirement: c.NativeConsole.DesignatedRequirement, Helper: privateHelper})
	if err != nil {
		return fail(err)
	}
	input, err := vault.NewNativeInputService(store, gate)
	if err != nil {
		return fail(err)
	}
	var provisioner vault.NativeKeyProvisioner = local
	if local == nil {
		provisioner, err = keychain.NewMasterKeyProvisioner(keychain.MasterKeyOptions{Alias: v.KeyAlias, Item: c.Keychain.Items[v.KeyAlias], BrokerRequirement: v.BrokerRequirement})
	}
	if err != nil {
		return fail(err)
	}
	setup, err := vault.NewNativeKeySetup(store, provisioner)
	if err != nil {
		return fail(err)
	}
	var records *vault.NativeRecordInputService
	if v.RecordRoot != "" {
		recordStore, err = vault.NewRecordStore(v.RecordRoot, v.KeyVersion, cipher)
		if err != nil {
			return fail(err)
		}
		records, err = vault.NewNativeRecordInputService(recordStore, gate)
		if err != nil {
			return fail(err)
		}
		setup, err = vault.NewNativeKeySetupWithRecords(store, provisioner, recordStore)
		if err != nil {
			return fail(err)
		}
	}
	return &nativeVaultRuntime{store: store, input: input, entry: entry, setup: setup, recordStore: recordStore, records: records}, nil
}
