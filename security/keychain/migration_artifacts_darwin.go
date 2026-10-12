//go:build darwin && cgo

package keychain

import (
	"context"
	"github.com/viant/mechanize/auth/nativepeer"
	"os"
)

type nativeRuntimeSignatureVerifier struct{}

func (nativeRuntimeSignatureVerifier) verify(ctx context.Context, role, path, requirement string) error {
	if role == "chrome-recovery" {
		if migrationContext(ctx) != nil || !exactRecoveryChromeRequirement(requirement) {
			return errMigrationUnavailable
		}
		combined := nativepeer.GoogleChromeSignerRequirement + " and (" + requirement + ")"
		if nativepeer.VerifyChromeExecutable(path, nativepeer.Options{ExpectedUID: uint32(os.Getuid()), DesignatedRequirement: combined}) != nil || migrationContext(ctx) != nil {
			return errMigrationUnavailable
		}
		return nil
	}
	if migrationContext(ctx) != nil || !runtimeRoleRequirement(role, requirement) {
		return errMigrationUnavailable
	}
	before, err := runtimeInventory(path)
	if err != nil {
		return errMigrationUnavailable
	}
	if !nativeReadinessStatic(path, requirement) || runtimeVerifyInventory(path, before) != nil || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	return nil
}

// No observer fallback exists. The host's actual Mechanize workflow must supply
// checked loaded-extension/process/terminal receipts; a guessed canonical path or
// raw callback returning nil is not a qualification adapter.
func newSignedRuntimeArtifacts(plan migrationRuntimeArtifactPlan, journalRoot string, observer migrationRuntimeObserver) (*migrationRuntimeArtifacts, error) {
	journal, err := newPrivateMigrationJournal(journalRoot, "mechanize-runtime-artifacts")
	if err != nil {
		return nil, errMigrationUnavailable
	}
	return newRuntimeArtifactsWith(plan, journal, observer, nativeRuntimeSignatureVerifier{})
}
