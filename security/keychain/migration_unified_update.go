//go:build darwin || linux

package keychain

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Same-path replacement is a whole sealed bundle operation. These read-only
// nested role views must match the complete old/new app inventories exactly.
func validUnifiedUpdateRuntime(p migrationRuntimeArtifactPlan) bool {
	home, err := migrationUserHomeDir()
	target := filepath.Join(home, "Applications", "Mechanize.app")
	if err != nil || p.Mode != unifiedUpdateMode || p.BrokerPath != filepath.Join(target, "Contents/Helpers/mechanize") || p.NewBrokerPath != "" || !validUnifiedUpdateConfig(p.BrokerPath, p.ConfigPath) || p.PreinstalledUnifiedApp || p.PreinstalledApprovalConsole || p.ApprovalConsole != nil || p.OriginalConsoleArtifact != nil || len(p.Artifacts) != 1 || len(p.LegacyArtifacts) != 3 || p.PreservedExtension == nil ||
		!migrationRequirement.MatchString(p.OldBrokerRequirement) || !migrationRequirement.MatchString(p.NewBrokerRequirement) || p.OldBrokerRequirement == p.NewBrokerRequirement || !migrationPackagedPath(p.ChromeExecutable) || !regexp.MustCompile(`^[a-p]{32}$`).MatchString(p.ExtensionID) || p.OldConsoleBirth == "" || len(p.OldConsoleBirth) > 128 || strings.ContainsRune(p.OldConsoleBirth, 0) {
		return false
	}
	app := p.Artifacts[0]
	if app.Role != "unified-app" || app.Target != target || !migrationPackagedPath(app.Candidate) || migrationPathsOverlap(app.Candidate, target) || !runtimeValidInventory(app.Old) || !runtimeValidInventory(app.New) || app.Old["."].Kind != "directory" || app.New["."].Kind != "directory" || runtimeInventoryDigest(app.Old) != app.OldDigest || runtimeInventoryDigest(app.New) != app.NewDigest || app.OldDigest == app.NewDigest || !runtimeRoleRequirement("console", app.OldRequirement) || !runtimeRoleRequirement("console", app.NewRequirement) {
		return false
	}
	for _, path := range []string{target, app.Candidate} {
		if migrationPathsOverlap(path, p.PreservedExtension.Path) {
			return false
		}
	}
	roles := map[string]bool{}
	for _, a := range p.LegacyArtifacts {
		if roles[a.Role] || !runtimeRoleRequirement(a.Role, a.OldRequirement) || !runtimeRoleRequirement(a.Role, a.NewRequirement) || runtimeInventoryDigest(a.Old) != a.OldDigest || runtimeInventoryDigest(a.New) != a.NewDigest {
			return false
		}
		roles[a.Role] = true
		if a.Role == "console" {
			if a.Target != target || a.Candidate != app.Candidate || a.OldDigest != app.OldDigest || a.NewDigest != app.NewDigest || a.OldRequirement != app.OldRequirement || a.NewRequirement != app.NewRequirement {
				return false
			}
			continue
		}
		name := map[string]string{"helper": "mechanize-native", "native-host": "mechanize-native-host"}[a.Role]
		if name == "" {
			return false
		}
		relative := filepath.Join("Contents/Helpers", name)
		if a.Target != filepath.Join(target, relative) || a.Candidate != filepath.Join(app.Candidate, relative) || len(a.Old) != 1 || len(a.New) != 1 || a.Old["."] != app.Old[relative] || a.New["."] != app.New[relative] {
			return false
		}
		if a.Role == "helper" && (p.ActiveHelperPath != a.Target || p.ActiveHelperRequirement != a.OldRequirement || p.ActiveHelperSHA256 != a.Old["."].SHA256) {
			return false
		}
	}
	for _, inventory := range []migrationRuntimeInventory{app.Old, app.New} {
		for _, name := range []string{"Contents/MacOS/MechanizeConsent", "Contents/Helpers/mechanize", "Contents/Helpers/mechanize-native", "Contents/Helpers/mechanize-native-host"} {
			v, ok := inventory[name]
			if !ok || v.Kind != "file" || v.Mode&0100 == 0 {
				return false
			}
		}
	}
	return len(roles) == 3
}
