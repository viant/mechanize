//go:build darwin || linux

package keychain

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestUnifiedStagePublishesWholeBundleRetainsOldBinaryAndExternalConfigBackup(t *testing.T) {
	legacy, p, ctx := migrationFileStageFixture(t)
	root := filepath.Dir(p.options.canonicalExecutable)
	candidate := filepath.Join(root, "candidate.app")
	target := filepath.Join(root, "Mechanize.app")
	if err := os.MkdirAll(filepath.Join(candidate, "Contents/Helpers"), 0700); err != nil {
		t.Fatal(err)
	}
	migrationWriteFixture(t, filepath.Join(candidate, "Contents/Helpers/mechanize"), "new-binary", 0700)
	inventory, err := runtimeInventory(candidate)
	if err != nil {
		t.Fatal(err)
	}
	p.unifiedInventorySHA256 = runtimeInventoryDigest(inventory)
	p.options.newCanonicalExecutable = filepath.Join(target, "Contents/Helpers/mechanize")
	backend := &migrationUnifiedStage{plan: p, candidateApp: candidate, targetApp: target, candidateConfig: legacy.candidateConfig, config: legacy.config, backup: legacy.backup, inventory: inventory, appRequirement: "fixture", quiescent: func(context.Context) error { return nil }, code: func(context.Context, string, string) error { return nil }, complete: func(context.Context, migrationStagePlan) error { return nil }, check: func() error { return nil }}
	if err = backend.verifyBeforePlacement(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err = backend.place(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err = backend.verifyComplete(ctx, p); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(p.options.canonicalExecutable)
	backup, _ := os.ReadFile(filepath.Join(legacy.backup, "config.json"))
	next, _ := os.ReadFile(legacy.config)
	if string(old) != "old-binary" || string(backup) != "old-config" || string(next) != "new-config" {
		t.Fatal("old custody/config preservation failed")
	}
	if backend.place(ctx, p) != errMigrationUnknown {
		t.Fatal("placement replay allowed")
	}
	if _, err = newMigrationFileStage(p, legacy.candidateBinary, legacy.candidateConfig, legacy.config, legacy.backup, backend.quiescent, backend.code, backend.complete); err == nil {
		t.Fatal("legacy writer admitted relocation")
	}
}

func TestPreinstalledUnifiedStageNeverRewritesBundle(t *testing.T) {
	legacy, p, ctx := migrationFileStageFixture(t)
	root := filepath.Dir(p.options.canonicalExecutable)
	candidate := filepath.Join(root, "candidate.app")
	target := filepath.Join(root, "Mechanize.app")
	if err := os.MkdirAll(filepath.Join(candidate, "Contents/Helpers"), 0700); err != nil {
		t.Fatal(err)
	}
	migrationWriteFixture(t, filepath.Join(candidate, "Contents/Helpers/mechanize"), "new-binary", 0700)
	inventory, err := runtimeInventory(candidate)
	if err != nil {
		t.Fatal(err)
	}
	p.unifiedInventorySHA256 = runtimeInventoryDigest(inventory)
	p.options.newCanonicalExecutable = filepath.Join(target, "Contents/Helpers/mechanize")
	p.preinstalledUnifiedApp = true
	if err := runtimeCopyInventory(candidate, target, inventory); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(target)
	originalDigest := migrationStageDigest(p)
	other := p
	other.preinstalledUnifiedApp = false
	if originalDigest == migrationStageDigest(other) {
		t.Fatal("adoption mode not journal bound")
	}
	backend := &migrationUnifiedStage{plan: p, candidateApp: candidate, targetApp: target, candidateConfig: legacy.candidateConfig, config: legacy.config, backup: legacy.backup, inventory: inventory, appRequirement: "fixture", quiescent: func(context.Context) error { return nil }, code: func(context.Context, string, string) error { return nil }, complete: func(context.Context, migrationStagePlan) error { return nil }, check: func() error { return nil }}
	installedBroker := filepath.Join(target, "Contents/Helpers/mechanize")
	if err = os.WriteFile(installedBroker, []byte("substitution"), 0700); err != nil {
		t.Fatal(err)
	}
	if backend.verifyBeforePlacement(ctx, p) == nil {
		t.Fatal("preinstalled substitution accepted")
	}
	unchanged, _ := os.ReadFile(legacy.config)
	if string(unchanged) != "old-config" {
		t.Fatal("rejected adoption changed config")
	}
	if err = os.WriteFile(installedBroker, []byte("new-binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = backend.verifyBeforePlacement(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err = backend.place(ctx, p); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(target)
	if !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
		t.Fatal("preinstalled bundle rewritten")
	}
	staged := filepath.Join(filepath.Dir(target), ".mechanize-relocation-"+p.transitionID)
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatal("preinstalled branch staged code")
	}
	if err = backend.verifyComplete(ctx, p); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(p.options.canonicalExecutable)
	backup, _ := os.ReadFile(filepath.Join(legacy.backup, "config.json"))
	next, _ := os.ReadFile(legacy.config)
	if string(old) != "old-binary" || string(backup) != "old-config" || string(next) != "new-config" {
		t.Fatal("old custody/config preservation failed")
	}
	if backend.place(ctx, p) != errMigrationUnknown {
		t.Fatal("placement replay allowed")
	}
	if _, err = newMigrationFileStage(p, legacy.candidateBinary, legacy.candidateConfig, legacy.config, legacy.backup, backend.quiescent, backend.code, backend.complete); err == nil {
		t.Fatal("legacy writer admitted relocation")
	}
}

func TestPreinstalledUnifiedStageFlagChangesDurableDigest(t *testing.T) {
	_, p, _ := migrationFileStageFixture(t)
	p.options.newCanonicalExecutable = "/Users/fixture/Applications/Mechanize.app/Contents/Helpers/mechanize"
	p.unifiedInventorySHA256 = migrationDigest([]byte("fixture"))
	p.preinstalledUnifiedApp = true
	if !validMigrationStagePlan(p) {
		t.Fatal("fixture invalid")
	}
	changed := p
	changed.preinstalledUnifiedApp = false
	if migrationStageDigest(p) == migrationStageDigest(changed) {
		t.Fatal("preinstalled flag unbound")
	}
}
