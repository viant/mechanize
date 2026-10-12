//go:build darwin && cgo

package host

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeVaultRuntimeConstructorSharesGateAndCustodyWithoutProvisioning(t *testing.T) {
	c := nativeVaultConfigFixture(t)
	dir, err := os.MkdirTemp("/private/tmp", "mechanize-vault-runtime-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	// Isolated constructor fixture bypasses only the production home-location
	// validation. It never registers the alias, inspects Keychain or calls setup.
	c.NativeVault.Root = filepath.Join(dir, "vault")
	runtime, err := configuredNativeVault(c)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.store.Close()
	if runtime.input.ExposureGate() == nil || runtime.input.ExposureGate() != runtime.entry.ExposureGate() || !runtime.setup.MatchesInput(runtime.input) {
		t.Fatal("configured providers do not share gate and storage")
	}
	entries, err := os.ReadDir(c.NativeVault.Root)
	if err != nil || len(entries) != 0 {
		t.Fatal("constructor created key/credential material")
	}
}
