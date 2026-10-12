//go:build darwin || linux

package keychain

import (
	"golang.org/x/sys/unix"
	"path/filepath"
	"strings"
)

const preserveExtensionMode = "preserve-extension-v1"

type migrationPreservedExtension struct {
	Path                 string                    `json:"path"`
	ExtensionID          string                    `json:"extensionID"`
	Inventory            migrationRuntimeInventory `json:"inventory"`
	InventorySHA256      string                    `json:"inventorySHA256"`
	RuntimeResourcesOnly bool                      `json:"runtimeResourcesOnly,omitempty"`
}

func validMigrationExtensionMode(plan migrationRuntimeArtifactPlan) bool {
	if unifiedRuntimeMode(plan.Mode) {
		if !validUnifiedRuntime(plan) {
			return false
		}
		plan.ConfigPath = ""
		plan.Mode = preserveExtensionMode
		plan.Artifacts = plan.LegacyArtifacts
		plan.LegacyArtifacts = nil
		plan.NewBrokerPath = ""
		plan.PreinstalledUnifiedApp = false
		plan.PreinstalledApprovalConsole = false
		plan.ApprovalConsole = nil
		plan.OriginalConsoleArtifact = nil
	}

	if plan.ConfigPath != "" || plan.NewBrokerPath != "" || len(plan.LegacyArtifacts) != 0 || plan.PreinstalledUnifiedApp || plan.PreinstalledApprovalConsole || plan.ApprovalConsole != nil || plan.OriginalConsoleArtifact != nil {
		return false
	}
	if !validChromeRecovery(plan) {
		return false
	}
	if plan.Mode == "" {
		return plan.PreservedExtension == nil && plan.ChromeRequirement == "" && validMigrationID(plan.ExtensionStorageSHA256) && len(plan.Artifacts) == 4
	}
	if plan.NativeRecordRoot != "" && !migrationPackagedPath(plan.NativeRecordRoot) {
		return false
	}
	p := plan.PreservedExtension
	if plan.Mode != preserveExtensionMode || p == nil || plan.ExtensionStorageSHA256 != "" || len(plan.Artifacts) != 3 || !migrationPackagedPath(p.Path) || p.ExtensionID != plan.ExtensionID || !validMigrationID(p.InventorySHA256) || runtimeInventoryDigest(p.Inventory) != p.InventorySHA256 || plan.ChromeRequirement == "" || len(plan.ChromeRequirement) > 4096 {
		return false
	}
	_, err := runtimeExtensionContract(p.Inventory, !p.RuntimeResourcesOnly)
	return err == nil
}
func migrationPathsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}
func (r *migrationRuntimeArtifacts) nonConsoleRoles() []string {
	if r.plan.Mode == preserveExtensionMode {
		return []string{"helper", "native-host"}
	}
	return []string{"helper", "native-host", "extension"}
}
func (r *migrationRuntimeArtifacts) verifyPreservedExtension() error {
	if r.plan.Mode == "" {
		return nil
	}
	p := r.plan.PreservedExtension
	if !validMigrationExtensionMode(r.plan) || p == nil || verifyPreservedInventory(p) != nil {
		return errMigrationUnavailable
	}
	key, err := runtimeExtensionIdentity(p.Path, p.Inventory)
	if err != nil {
		return err
	}
	if key != "" {
		id, err := runtimeExtensionIDFromKey(key)
		if err != nil || id != p.ExtensionID {
			return errMigrationUnavailable
		}
	}
	return nil
}

// Preservation mode narrows the complete write set, including recovery state.
// It never opens a profile/storage path or uses storage equality as evidence.
func validPreservationPlacement(p migrationPackagedInstallPlan, enrolled migrationPackagedEnrollment) bool {
	if unifiedRuntimeMode(p.Runtime.Mode) {
		if !validMigrationExtensionMode(p.Runtime) || (p.Runtime.Mode == unifiedAppMode && (enrolled.Version != 2 || enrolled.NewCanonicalExecutable != p.Runtime.NewBrokerPath)) || (p.Runtime.Mode == unifiedUpdateMode && (enrolled.Version != 3 || !validUnifiedUpdateConfig(enrolled.CanonicalExecutable, enrolled.Config.Path))) {
			return false
		}
		root := filepath.Dir(enrolled.CanonicalExecutable)
		if p.Runtime.Mode == unifiedUpdateMode {
			root = filepath.Dir(enrolled.Config.Path)
		}
		preserved := p.Runtime.PreservedExtension.Path
		for _, path := range []string{p.Backup, p.StageJournalRoot, p.ArtifactJournalRoot, enrolled.JournalRoot, enrolled.Config.Path} {
			if !migrationPackagedPath(path) || !strings.HasPrefix(path, root+string(filepath.Separator)) || migrationPathsOverlap(path, preserved) {
				return false
			}
		}
		app := p.Runtime.Artifacts[0]
		for _, path := range []string{app.Target, app.Candidate, p.BrokerCandidate.Path, p.ConfigCandidate.Path} {
			if migrationPathsOverlap(path, preserved) {
				return false
			}
		}
		return p.BrokerCandidate.Path == filepath.Join(app.Candidate, "Contents/Helpers/mechanize") && p.BrokerCandidate.SHA256 == app.New["Contents/Helpers/mechanize"].SHA256
	}

	if p.Runtime.Mode == "" {
		return p.Runtime.PreservedExtension == nil
	}
	if !validMigrationExtensionMode(p.Runtime) {
		return false
	}
	root := filepath.Dir(enrolled.CanonicalExecutable)
	preserved := p.Runtime.PreservedExtension.Path
	paths := []string{p.Backup, p.StageJournalRoot, p.ArtifactJournalRoot, enrolled.JournalRoot, enrolled.Config.Path, enrolled.CanonicalExecutable}
	for _, a := range p.Runtime.Artifacts {
		if a.Role == "extension" {
			return false
		}
		paths = append(paths, a.Target)
	}
	for _, path := range paths {
		if !migrationPackagedPath(path) || !strings.HasPrefix(path, root+string(filepath.Separator)) || migrationPathsOverlap(path, preserved) {
			return false
		}
	}
	// Candidate resources remain read-only but cannot alias preserved code.
	for _, a := range p.Runtime.Artifacts {
		if migrationPathsOverlap(a.Candidate, preserved) {
			return false
		}
	}
	for _, path := range []string{p.BrokerCandidate.Path, p.ConfigCandidate.Path} {
		if migrationPathsOverlap(path, preserved) {
			return false
		}
	}
	return true
}

func preservedChromeConfigMatches(runtime migrationRuntimeArtifactPlan, old map[string]any) bool {
	if runtime.Mode != preserveExtensionMode && !unifiedRuntimeMode(runtime.Mode) {
		return true
	}
	chrome, ok := old["chrome"].(map[string]any)
	if !ok {
		return false
	}
	trust, ok := chrome["processTrust"].(map[string]any)
	return ok && trust["chromeRequirement"] == runtime.ChromeRequirement && trust["chromeExecutable"] == runtime.ChromeExecutable
}

// The explicit source-tree variant reads only reviewed runtime names. It never
// enumerates sibling entries, package-manager directories, or profile data.
func verifyPreservedInventory(p *migrationPreservedExtension) error {
	if !p.RuntimeResourcesOnly {
		return runtimeVerifyInventory(p.Path, p.Inventory)
	}
	if _, err := runtimeExtensionContract(p.Inventory, false); err != nil {
		return err
	}
	parent, err := runtimeArtifactParent(p.Path)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, filepath.Base(p.Path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errMigrationUnavailable
	}
	defer unix.Close(fd)
	var before, after, entry unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !runtimeOwned(before) || uint32(before.Mode)&0777 != p.Inventory["."].Mode {
		return errMigrationUnavailable
	}
	for _, name := range runtimeExtensionFiles {
		if _, err := runtimeReadFile(filepath.Join(p.Path, name), p.Inventory[name]); err != nil {
			return err
		}
	}
	if unix.Fstat(fd, &after) != nil || unix.Fstatat(parent, filepath.Base(p.Path), &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !runtimeSame(before, after) || !runtimeSame(before, entry) {
		return errMigrationUnavailable
	}
	return nil
}
