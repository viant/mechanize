//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

// A relocation publishes one complete signed application. Legacy code remains
// untouched; configuration backup and all uncertain state stay in the private
// runtime. This backend must be driven by the durable stage controller.
type migrationUnifiedStage struct {
	plan                                                     migrationStagePlan
	candidateApp, targetApp, candidateConfig, config, backup string
	inventory                                                migrationRuntimeInventory
	appRequirement                                           string
	quiescent                                                func(context.Context) error
	code                                                     func(context.Context, string, string) error
	complete                                                 func(context.Context, migrationStagePlan) error
	check                                                    func() error
	attempted                                                bool
	updateArtifact                                           *migrationRuntimeArtifact
}

func newMigrationUnifiedStage(p migrationStagePlan, candidateApp, targetApp, candidateConfig, config, backup string, inventory migrationRuntimeInventory, appRequirement string,
	quiescent func(context.Context) error, code func(context.Context, string, string) error, complete func(context.Context, migrationStagePlan) error, check func() error) (*migrationUnifiedStage, error) {
	home, err := migrationUserHomeDir()
	if err != nil || !validMigrationStagePlan(p) || p.options.newCanonicalExecutable == "" || targetApp != filepath.Join(home, "Applications", "Mechanize.app") || p.options.destinationExecutable() != filepath.Join(targetApp, "Contents", "Helpers", "mechanize") || !runtimeRoleRequirement("console", appRequirement) || !runtimeValidInventory(inventory) || inventory["."].Kind != "directory" || runtimeInventoryDigest(inventory) != p.unifiedInventorySHA256 || inventory["Contents/Helpers/mechanize"].SHA256 != p.newBinarySHA256 || quiescent == nil || code == nil || complete == nil || check == nil {
		return nil, errMigrationUnavailable
	}
	for _, path := range []string{candidateApp, candidateConfig, config, backup} {
		if !migrationPackagedPath(path) || migrationPathsOverlap(path, targetApp) {
			return nil, errMigrationUnavailable
		}
	}
	if filepath.Dir(config) != filepath.Dir(p.options.canonicalExecutable) || filepath.Base(config) != "config.json" || filepath.Dir(backup) != filepath.Dir(config) {
		return nil, errMigrationUnavailable
	}
	return &migrationUnifiedStage{plan: p, candidateApp: candidateApp, targetApp: targetApp, candidateConfig: candidateConfig, config: config, backup: backup, inventory: runtimeInventoryCopy(inventory), appRequirement: appRequirement, quiescent: quiescent, code: code, complete: complete, check: check}, nil
}
func (s *migrationUnifiedStage) valid(ctx context.Context, p migrationStagePlan) bool {
	return migrationContext(ctx) == nil && migrationStageDigest(s.plan) == migrationStageDigest(p) && s.plan.transitionID == p.transitionID && bytes.Equal(s.plan.itemIdentity, p.itemIdentity) && s.check() == nil
}
func (s *migrationUnifiedStage) verifyBeforePlacement(ctx context.Context, p migrationStagePlan) error {
	if !s.valid(ctx, p) || s.quiescent(ctx) != nil {
		return errMigrationUnavailable
	}
	if s.updateArtifact != nil {
		if runtimeVerifyInventory(s.targetApp, s.updateArtifact.Old) != nil || s.code(ctx, s.targetApp, s.updateArtifact.OldRequirement) != nil {
			return errMigrationUnavailable
		}
	} else if p.preinstalledUnifiedApp {
		if runtimeVerifyInventory(s.targetApp, s.inventory) != nil || s.code(ctx, s.targetApp, s.appRequirement) != nil || s.code(ctx, p.options.destinationExecutable(), p.options.newRequirement) != nil || runtimeVerifyInventory(s.targetApp, s.inventory) != nil {
			return errMigrationUnavailable
		}
	} else if _, err := os.Lstat(s.targetApp); !os.IsNotExist(err) {
		return errMigrationUnavailable
	}
	for _, v := range []struct {
		path, digest string
		executable   bool
	}{{p.options.canonicalExecutable, p.oldBinarySHA256, true}, {s.config, p.oldConfigSHA256, false}, {s.candidateConfig, p.newConfigSHA256, false}} {
		if digest, err := migrationFileDigest(v.path, v.executable); err != nil || digest != v.digest {
			return errMigrationUnavailable
		}
	}
	if runtimeVerifyInventory(s.candidateApp, s.inventory) != nil || s.code(ctx, p.options.canonicalExecutable, p.options.oldRequirement) != nil || s.code(ctx, s.candidateApp, s.appRequirement) != nil || s.code(ctx, filepath.Join(s.candidateApp, "Contents/Helpers/mechanize"), p.options.newRequirement) != nil {
		return errMigrationUnavailable
	}
	return nil
}
func (s *migrationUnifiedStage) place(ctx context.Context, p migrationStagePlan) error {
	if s.attempted || s.verifyBeforePlacement(ctx, p) != nil {
		return errMigrationUnknown
	}
	s.attempted = true
	if migrationCreateBackupDirectory(ctx, s.backup) != nil || migrationCopyFile(ctx, s.config, filepath.Join(s.backup, "config.json"), p.oldConfigSHA256, false, false) != nil {
		return errMigrationUnknown
	}
	if s.updateArtifact != nil {
		if s.exchangeUpdate(ctx, p) != nil {
			return errMigrationUnknown
		}
	} else if !p.preinstalledUnifiedApp {
		staged := filepath.Join(filepath.Dir(s.targetApp), ".mechanize-relocation-"+p.transitionID)
		if runtimeCopyInventory(s.candidateApp, staged, s.inventory) != nil || s.code(ctx, staged, s.appRequirement) != nil || !s.valid(ctx, p) || s.quiescent(ctx) != nil {
			return errMigrationUnknown
		}
		parent, err := runtimeArtifactParent(s.targetApp)
		if err != nil {
			return errMigrationUnknown
		}
		defer unix.Close(parent)
		if migrationPublishAbsent(parent, filepath.Base(staged), filepath.Base(s.targetApp)) != nil || unix.Fsync(parent) != nil || runtimeVerifyInventory(s.targetApp, s.inventory) != nil || s.code(ctx, s.targetApp, s.appRequirement) != nil || !s.valid(ctx, p) {
			return errMigrationUnknown
		}
	} else if runtimeVerifyInventory(s.targetApp, s.inventory) != nil || s.code(ctx, s.targetApp, s.appRequirement) != nil || s.code(ctx, p.options.destinationExecutable(), p.options.newRequirement) != nil || runtimeVerifyInventory(s.targetApp, s.inventory) != nil {
		return errMigrationUnknown
	}

	if s.quiescent(ctx) != nil || !s.valid(ctx, p) {
		return errMigrationUnknown
	}
	if migrationReplaceFile(ctx, s.candidateConfig, s.config, p.newConfigSHA256, p.oldConfigSHA256, false, p.transitionID, s.check) != nil {
		return errMigrationUnknown
	}
	return nil
}
func (s *migrationUnifiedStage) verifyComplete(ctx context.Context, p migrationStagePlan) error {
	if !s.valid(ctx, p) || runtimeVerifyInventory(s.targetApp, s.inventory) != nil || s.code(ctx, s.targetApp, s.appRequirement) != nil || s.code(ctx, p.options.destinationExecutable(), p.options.newRequirement) != nil {
		return errMigrationUnavailable
	}
	if digest, err := migrationFileDigest(s.config, false); err != nil || digest != p.newConfigSHA256 {
		return errMigrationUnavailable
	}
	oldBroker := p.options.canonicalExecutable
	if s.updateArtifact != nil {
		retained := runtimeRetainedArtifact(*s.updateArtifact, p.transitionID)
		if runtimeVerifyInventory(retained, s.updateArtifact.Old) != nil || s.code(ctx, retained, s.updateArtifact.OldRequirement) != nil {
			return errMigrationUnavailable
		}
		oldBroker = filepath.Join(retained, "Contents/Helpers/mechanize")
	}
	if digest, err := migrationFileDigest(oldBroker, true); err != nil || digest != p.oldBinarySHA256 {
		return errMigrationUnavailable
	}
	return s.complete(ctx, p)
}

func newMigrationUnifiedUpdateStage(p migrationStagePlan, app migrationRuntimeArtifact, candidateConfig, config, backup string,
	quiescent func(context.Context) error, code func(context.Context, string, string) error, complete func(context.Context, migrationStagePlan) error, check func() error) (*migrationUnifiedStage, error) {
	if !validMigrationStagePlan(p) || p.updateConfig != config || p.options.newCanonicalExecutable != "" || !validUnifiedUpdateConfig(p.options.canonicalExecutable, config) || filepath.Join(app.Target, "Contents/Helpers/mechanize") != p.options.canonicalExecutable || app.Role != "unified-app" || !runtimeRoleRequirement("console", app.OldRequirement) || !runtimeRoleRequirement("console", app.NewRequirement) || !runtimeValidInventory(app.Old) || !runtimeValidInventory(app.New) || runtimeInventoryDigest(app.Old) != p.updateOldInventorySHA256 || runtimeInventoryDigest(app.New) != p.unifiedInventorySHA256 || app.Old["Contents/Helpers/mechanize"].SHA256 != p.oldBinarySHA256 || app.New["Contents/Helpers/mechanize"].SHA256 != p.newBinarySHA256 || quiescent == nil || code == nil || complete == nil || check == nil {
		return nil, errMigrationUnavailable
	}
	for _, path := range []string{app.Candidate, candidateConfig, config, backup} {
		if !migrationPackagedPath(path) || migrationPathsOverlap(path, app.Target) {
			return nil, errMigrationUnavailable
		}
	}
	if filepath.Dir(backup) != filepath.Dir(config) || migrationPathsOverlap(app.Candidate, config) || migrationPathsOverlap(app.Candidate, backup) {
		return nil, errMigrationUnavailable
	}
	copy := app
	copy.Old = runtimeInventoryCopy(app.Old)
	copy.New = runtimeInventoryCopy(app.New)
	return &migrationUnifiedStage{plan: p, candidateApp: app.Candidate, targetApp: app.Target, candidateConfig: candidateConfig, config: config, backup: backup, inventory: copy.New, appRequirement: app.NewRequirement, quiescent: quiescent, code: code, complete: complete, check: check, updateArtifact: &copy}, nil
}

// Reuse the same descriptor-checked atomic exchange primitive as artifact
// placement. All staging writes are siblings of the app, never inside its seal.
func (s *migrationUnifiedStage) exchangeUpdate(ctx context.Context, p migrationStagePlan) error {
	a := *s.updateArtifact
	retained := runtimeRetainedArtifact(a, p.transitionID)
	if runtimeVerifyInventory(a.Target, a.Old) != nil || runtimeCopyInventory(a.Candidate, retained, a.New) != nil || s.code(ctx, retained, a.NewRequirement) != nil {
		return errMigrationUnknown
	}
	dir, err := runtimeArtifactParent(a.Target)
	if err != nil {
		return errMigrationUnknown
	}
	defer unix.Close(dir)
	old, err := unix.Openat(dir, filepath.Base(a.Target), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errMigrationUnknown
	}
	defer unix.Close(old)
	fresh, err := unix.Openat(dir, filepath.Base(retained), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errMigrationUnknown
	}
	defer unix.Close(fresh)
	if runtimeEntryMatches(dir, filepath.Base(a.Target), old) != nil || runtimeEntryMatches(dir, filepath.Base(retained), fresh) != nil || runtimeParentMatches(a.Target, dir) != nil || !s.valid(ctx, p) || s.quiescent(ctx) != nil || runtimeVerifyInventory(a.Target, a.Old) != nil || runtimeVerifyInventory(retained, a.New) != nil {
		return errMigrationUnknown
	}
	if migrationExchangeNames(dir, filepath.Base(retained), filepath.Base(a.Target)) != nil {
		return errMigrationUnknown
	}
	if unix.Fsync(dir) != nil || runtimeEntryMatches(dir, filepath.Base(retained), old) != nil || runtimeEntryMatches(dir, filepath.Base(a.Target), fresh) != nil || runtimeParentMatches(a.Target, dir) != nil || !s.valid(ctx, p) || runtimeVerifyInventory(a.Target, a.New) != nil || runtimeVerifyInventory(retained, a.Old) != nil || s.code(ctx, a.Target, a.NewRequirement) != nil || s.code(ctx, retained, a.OldRequirement) != nil {
		return errMigrationUnknown
	}
	return nil
}
