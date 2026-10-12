//go:build darwin || linux

package keychain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func unifiedRuntimeFixture(t *testing.T) (*runtimePlacementFixture, migrationRuntimeArtifactPlan) {
	f := preserveRuntimeFixture(t)
	plan := f.r.plan
	console := f.r.artifact("console")
	app := console.Candidate
	if err := os.Mkdir(filepath.Join(app, "Contents/Helpers"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"helper", "native-host"} {
		a := f.r.artifact(role)
		name := "mechanize-native"
		if role == "native-host" {
			name = "mechanize-native-host"
		}
		raw, err := os.ReadFile(a.Candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(app, "Contents/Helpers", name), raw, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(app, "Contents/Helpers/mechanize"), []byte("new-broker"), 0700); err != nil {
		t.Fatal(err)
	}
	inventory, err := runtimeInventory(app)
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	target := filepath.Join(home, "Applications/Mechanize.app")
	plan.Mode = unifiedAppMode
	plan.NewBrokerPath = filepath.Join(target, "Contents/Helpers/mechanize")
	plan.LegacyArtifacts = append([]migrationRuntimeArtifact{}, plan.Artifacts...)
	for i := range plan.LegacyArtifacts {
		a := &plan.LegacyArtifacts[i]
		switch a.Role {
		case "console":
			a.New = inventory
			a.NewDigest = runtimeInventoryDigest(inventory)
		default:
			name := "mechanize-native"
			if a.Role == "native-host" {
				name = "mechanize-native-host"
			}
			relative := "Contents/Helpers/" + name
			a.Candidate = filepath.Join(app, relative)
			a.New = migrationRuntimeInventory{".": inventory[relative]}
			a.NewDigest = runtimeInventoryDigest(a.New)
		}
	}
	plan.Artifacts = []migrationRuntimeArtifact{{Role: "unified-app", Target: target, Candidate: app, New: inventory, NewDigest: runtimeInventoryDigest(inventory), NewRequirement: console.NewRequirement}}
	return f, plan
}
func TestUnifiedRuntimeConstructorPinsWholeBundleAndReadOnlyLegacyArtifacts(t *testing.T) {
	f, plan := unifiedRuntimeFixture(t)
	if !validUnifiedRuntime(plan) {
		t.Fatal("closed unified fixture invalid")
	}
	if _, err := newRuntimeArtifactsWith(plan, f.journal, f.observer, f.signatures); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"destination", "old", "nested", "missingLegacy"} {
		bad := plan
		bad.Artifacts = append([]migrationRuntimeArtifact{}, plan.Artifacts...)
		switch mode {
		case "destination":
			bad.NewBrokerPath = plan.BrokerPath
		case "old":
			bad.Artifacts[0].OldRequirement = "unexpected"
		case "nested":
			bad.Artifacts[0].New = runtimeInventoryCopy(plan.Artifacts[0].New)
			delete(bad.Artifacts[0].New, "Contents/Helpers/mechanize")
		case "missingLegacy":
			bad.LegacyArtifacts = nil
		}
		if validUnifiedRuntime(bad) {
			t.Fatal("invalid unified plan accepted", mode)
		}
	}
}

func TestUnifiedInstallPlanDecoderBindsBothPathsAndPreservesV1Separation(t *testing.T) {
	_, runtime := unifiedRuntimeFixture(t)
	root := filepath.Dir(runtime.BrokerPath)
	enrolled := migrationPackagedEnrollment{Version: 2, CanonicalExecutable: runtime.BrokerPath, NewCanonicalExecutable: runtime.NewBrokerPath, OldRequirement: runtime.OldBrokerRequirement, NewRequirement: runtime.NewBrokerRequirement, Config: migrationPackagedResource{Path: filepath.Join(root, "config.json"), SHA256: strings.Repeat("a", 64)}, JournalRoot: filepath.Join(root, ".secret", "mechanize-custody-migration"), InstallPlan: &migrationPackagedResource{Path: filepath.Join(root, "plan.json"), SHA256: strings.Repeat("b", 64)}}
	p := migrationPackagedInstallPlan{Version: 2, OldBrokerSHA256: strings.Repeat("c", 64), BrokerCandidate: migrationPackagedResource{Path: filepath.Join(runtime.Artifacts[0].Candidate, "Contents/Helpers/mechanize"), SHA256: runtime.Artifacts[0].New["Contents/Helpers/mechanize"].SHA256}, ConfigCandidate: migrationPackagedResource{Path: filepath.Join(root, "next-config.json"), SHA256: strings.Repeat("d", 64)}, Backup: filepath.Join(root, "backup"), StageJournalRoot: filepath.Join(root, ".secret", "mechanize-runtime-staging"), ArtifactJournalRoot: filepath.Join(root, ".secret", "mechanize-runtime-artifacts"), NewSourceRoot: filepath.Join(root, "source"), Runtime: runtime}
	raw, _ := json.Marshal(p)
	if _, err := decodeMigrationInstallPlan(raw, enrolled); err != nil {
		_, stageErr := newRuntimeStageJournal(p.StageJournalRoot)
		_, artifactErr := newPrivateMigrationJournal(p.ArtifactJournalRoot, "mechanize-runtime-artifacts")
		t.Fatal(err, validUnifiedRuntime(runtime), validMigrationExtensionMode(runtime), validPreservationPlacement(p, enrolled), stageErr, artifactErr)
	}
	bad := enrolled
	bad.NewCanonicalExecutable = runtime.BrokerPath
	if _, err := decodeMigrationInstallPlan(raw, bad); err == nil {
		t.Fatal("old/new path substitution accepted")
	}
	bad = enrolled
	bad.Version = 1
	bad.NewCanonicalExecutable = ""
	if _, err := decodeMigrationInstallPlan(raw, bad); err == nil {
		t.Fatal("v2 admitted through v1 enrollment")
	}
	p.ConfigCandidate.Path = filepath.Join(runtime.PreservedExtension.Path, "config.json")
	raw, _ = json.Marshal(p)
	if _, err := decodeMigrationInstallPlan(raw, enrolled); err == nil {
		t.Fatal("preserved extension write overlap accepted")
	}
}

func TestApprovalCompatibilitySeparatesAndRechecksOriginalConsole(t *testing.T) {
	f, plan := unifiedRuntimeFixture(t)
	plan.PreinstalledUnifiedApp = true
	plan.PreinstalledApprovalConsole = true
	plan.OldConsoleBirth = "1800000000:2"
	plan.ApprovalConsole = &migrationApprovalConsole{InstalledPath: plan.Artifacts[0].Target, Requirement: plan.Artifacts[0].NewRequirement, Birth: plan.OldConsoleBirth}
	for i := range plan.LegacyArtifacts {
		a := &plan.LegacyArtifacts[i]
		if a.Role != "console" {
			continue
		}
		plan.OriginalConsoleArtifact = &migrationOriginalConsoleArtifact{Path: a.Target, Requirement: a.OldRequirement, Inventory: runtimeInventoryCopy(a.Old), InventorySHA256: a.OldDigest}
		a.Target = a.Candidate
		a.Old = runtimeInventoryCopy(a.New)
		a.OldDigest = a.NewDigest
		a.OldRequirement = a.NewRequirement
	}
	if !validUnifiedRuntime(plan) {
		t.Fatal("truthful compatibility metadata rejected")
	}
	r, err := newRuntimeArtifactsWith(plan, f.journal, f.observer, f.signatures)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.verifyOriginalConsole(f.ctx); err != nil {
		t.Fatal("original console proof failed", err)
	}
	compatibility := r.artifact("console")
	if err = r.verifyArtifact(f.ctx, compatibility, compatibility.Target, false); err != nil {
		t.Fatal("approving console pin falsely treated as old broker image", err)
	}
	bad := plan
	bad.PreinstalledApprovalConsole = false
	if validUnifiedRuntime(bad) {
		t.Fatal("unmarked candidate alias allowed")
	}
	bad = plan
	approval := *plan.ApprovalConsole
	approval.Birth = "1:1"
	bad.ApprovalConsole = &approval
	if validUnifiedRuntime(bad) {
		t.Fatal("substituted current birth allowed")
	}
	original := plan.OriginalConsoleArtifact
	if err = os.WriteFile(filepath.Join(original.Path, "Contents/Info.plist"), []byte("substitution"), 0600); err != nil {
		t.Fatal(err)
	}
	if r.verifyOriginalConsole(f.ctx) == nil {
		t.Fatal("changed original artifact accepted")
	}
}
