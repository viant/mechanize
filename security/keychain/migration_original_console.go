//go:build darwin || linux

package keychain

import (
	"context"
	"path/filepath"
)

type migrationOriginalConsoleArtifact struct {
	Path            string                    `json:"path"`
	Requirement     string                    `json:"requirement"`
	Inventory       migrationRuntimeInventory `json:"inventory"`
	InventorySHA256 string                    `json:"inventorySHA256"`
}

func validApprovalCompatibility(plan migrationRuntimeArtifactPlan) bool {
	if !plan.PreinstalledApprovalConsole {
		return plan.ApprovalConsole == nil && plan.OriginalConsoleArtifact == nil
	}
	if !plan.PreinstalledUnifiedApp || len(plan.Artifacts) != 1 || !validApprovalConsole(plan.ApprovalConsole, plan.NewBrokerPath, plan.Artifacts[0].NewRequirement) || plan.ApprovalConsole.Birth != plan.OldConsoleBirth {
		return false
	}
	original := plan.OriginalConsoleArtifact
	return original != nil && original.Path == filepath.Join(filepath.Dir(plan.BrokerPath), "Mechanize Permissions.app") && !migrationPathsOverlap(original.Path, plan.Artifacts[0].Candidate) && runtimeRoleRequirement("console", original.Requirement) && runtimeValidInventory(original.Inventory) && original.Inventory["."].Kind == "directory" && runtimeInventoryDigest(original.Inventory) == original.InventorySHA256
}
func (r *migrationRuntimeArtifacts) verifyOriginalConsole(ctx context.Context) error {
	if !r.plan.PreinstalledApprovalConsole {
		return nil
	}
	if !validApprovalCompatibility(r.plan) {
		return errMigrationUnavailable
	}
	o := r.plan.OriginalConsoleArtifact
	return r.verifyArtifact(ctx, migrationRuntimeArtifact{Role: "console", Target: o.Path, Old: o.Inventory, OldRequirement: o.Requirement}, o.Path, false)
}
