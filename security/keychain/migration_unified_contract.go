//go:build darwin || linux

package keychain

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Closed relocation schema. Legacy artifacts are retained read-only, never
// admitted to the unified writer's one-artifact set.
func validUnifiedRuntime(plan migrationRuntimeArtifactPlan) bool {
	if plan.Mode == unifiedUpdateMode {
		return validUnifiedUpdateRuntime(plan)
	}
	if plan.ConfigPath != "" || !migrationPackagedPath(plan.BrokerPath) || !migrationRequirement.MatchString(plan.OldBrokerRequirement) || !migrationRequirement.MatchString(plan.NewBrokerRequirement) || plan.OldBrokerRequirement == plan.NewBrokerRequirement || !migrationPackagedPath(plan.ActiveHelperPath) || !runtimeRoleRequirement("helper", plan.ActiveHelperRequirement) || !validMigrationID(plan.ActiveHelperSHA256) || !migrationPackagedPath(plan.ChromeExecutable) || !regexp.MustCompile(`^[a-p]{32}$`).MatchString(plan.ExtensionID) || plan.OldConsoleBirth == "" || len(plan.OldConsoleBirth) > 128 || strings.ContainsRune(plan.OldConsoleBirth, 0) {
		return false
	}
	home, err := migrationUserHomeDir()
	if err != nil {
		return false
	}
	target := filepath.Join(home, "Applications", "Mechanize.app")
	if !validApprovalCompatibility(plan) || plan.Mode != unifiedAppMode || plan.NewBrokerPath != filepath.Join(target, "Contents/Helpers/mechanize") || len(plan.Artifacts) != 1 || len(plan.LegacyArtifacts) != 3 || plan.PreservedExtension == nil {
		return false
	}
	app := plan.Artifacts[0]
	if app.Role != "unified-app" || app.Target != target || app.OldRequirement != "" || app.OldDigest != "" || len(app.Old) != 0 || !runtimeRoleRequirement("console", app.NewRequirement) || !runtimeValidInventory(app.New) || app.New["."].Kind != "directory" || runtimeInventoryDigest(app.New) != app.NewDigest || !migrationPackagedPath(app.Candidate) || migrationPathsOverlap(app.Target, app.Candidate) {
		return false
	}
	roles := map[string]bool{}
	for _, a := range plan.LegacyArtifacts {
		compatibility := plan.PreinstalledApprovalConsole && a.Role == "console"
		if roles[a.Role] || !runtimeValidInventory(a.Old) || !runtimeValidInventory(a.New) || runtimeInventoryDigest(a.New) != a.NewDigest || runtimeInventoryDigest(a.Old) != a.OldDigest || !runtimeRoleRequirement(a.Role, a.OldRequirement) || !runtimeRoleRequirement(a.Role, a.NewRequirement) || !migrationPackagedPath(a.Target) || migrationPathsOverlap(a.Target, target) || (!compatibility && migrationPathsOverlap(a.Target, app.Candidate)) || migrationPathsOverlap(plan.BrokerPath, app.Candidate) {
			return false
		}
		roles[a.Role] = true
		expected := map[string]string{"helper": "mechanize-native", "native-host": "mechanize-native-host", "console": "Mechanize Permissions.app"}[a.Role]
		if expected == "" || (!compatibility && (filepath.Dir(a.Target) != filepath.Dir(plan.BrokerPath) || filepath.Base(a.Target) != expected)) || migrationPathsOverlap(a.Target, plan.PreservedExtension.Path) || migrationPathsOverlap(app.Candidate, plan.PreservedExtension.Path) || (a.Role != "console" && a.Old["."].Kind != "file") || (a.Role == "console" && a.Old["."].Kind != "directory") {
			return false
		}
		if compatibility && (a.Target != app.Candidate || a.OldRequirement != app.NewRequirement || a.OldDigest != app.NewDigest) {
			return false
		}
		var relative string
		switch a.Role {
		case "helper":
			relative = "Contents/Helpers/mechanize-native"
		case "native-host":
			relative = "Contents/Helpers/mechanize-native-host"
		case "console":
			if a.Candidate != app.Candidate || a.NewRequirement != app.NewRequirement || a.NewDigest != app.NewDigest {
				return false
			}
			continue
		default:
			return false
		}
		entry, ok := app.New[relative]
		if !ok || entry.Kind != "file" || a.Candidate != filepath.Join(app.Candidate, relative) || len(a.New) != 1 || a.New["."] != entry || a.NewDigest != runtimeInventoryDigest(a.New) {
			return false
		}
	}
	for _, name := range []string{"Contents/MacOS/MechanizeConsent", "Contents/Helpers/mechanize", "Contents/Helpers/mechanize-native", "Contents/Helpers/mechanize-native-host"} {
		entry, ok := app.New[name]
		if !ok || entry.Kind != "file" || entry.Mode&0100 == 0 {
			return false
		}
	}
	return len(roles) == 3
}
