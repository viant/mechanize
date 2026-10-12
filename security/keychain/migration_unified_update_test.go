//go:build darwin || linux

package keychain

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func unifiedUpdateFixture(t *testing.T) (*runtimePlacementFixture, migrationRuntimeArtifactPlan) {
	f, p := unifiedRuntimeFixture(t)
	p.ConfigPath = filepath.Join(filepath.Dir(f.p.options.canonicalExecutable), "config.json")
	p.Mode = unifiedUpdateMode
	p.BrokerPath = p.NewBrokerPath
	p.NewBrokerPath = ""
	app := &p.Artifacts[0]
	app.Old = runtimeInventoryCopy(app.New)
	for name, e := range app.Old {
		if e.Kind == "file" {
			e.SHA256 = migrationDigest([]byte("old:" + name))
			app.Old[name] = e
		}
	}
	app.OldDigest = runtimeInventoryDigest(app.Old)
	app.OldRequirement = f.r.artifact("console").OldRequirement
	for i := range p.LegacyArtifacts {
		a := &p.LegacyArtifacts[i]
		if a.Role == "console" {
			a.Target = app.Target
			a.Old = runtimeInventoryCopy(app.Old)
			a.OldDigest = app.OldDigest
			continue
		}
		name := map[string]string{"helper": "mechanize-native", "native-host": "mechanize-native-host"}[a.Role]
		a.Target = filepath.Join(app.Target, "Contents/Helpers", name)
		a.Old = migrationRuntimeInventory{".": app.Old["Contents/Helpers/"+name]}
		a.OldDigest = runtimeInventoryDigest(a.Old)
		if a.Role == "helper" {
			p.ActiveHelperPath = a.Target
			p.ActiveHelperRequirement = a.OldRequirement
			p.ActiveHelperSHA256 = a.Old["."].SHA256
		}
	}
	return f, p
}
func TestUnifiedUpdateContractPinsSamePathBundleAndExternalConfig(t *testing.T) {
	f, r := unifiedUpdateFixture(t)
	if !validUnifiedUpdateRuntime(r) {
		t.Fatal("fixture rejected")
	}
	if _, err := newRuntimeArtifactsWith(r, f.journal, f.observer, f.signatures); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(f.p.options.canonicalExecutable)
	e := migrationPackagedEnrollment{Version: 3, CanonicalExecutable: r.BrokerPath, OldRequirement: r.OldBrokerRequirement, NewRequirement: r.NewBrokerRequirement, Config: migrationPackagedResource{Path: filepath.Join(root, "config.json"), SHA256: strings.Repeat("a", 64)}, JournalRoot: filepath.Join(root, ".secret/mechanize-custody-migration"), InstallPlan: &migrationPackagedResource{Path: filepath.Join(root, "plan.json"), SHA256: strings.Repeat("b", 64)}}
	p := migrationPackagedInstallPlan{Version: 3, OldBrokerSHA256: r.Artifacts[0].Old["Contents/Helpers/mechanize"].SHA256, BrokerCandidate: migrationPackagedResource{Path: filepath.Join(r.Artifacts[0].Candidate, "Contents/Helpers/mechanize"), SHA256: r.Artifacts[0].New["Contents/Helpers/mechanize"].SHA256}, ConfigCandidate: migrationPackagedResource{Path: filepath.Join(root, "candidate.json"), SHA256: strings.Repeat("c", 64)}, Backup: filepath.Join(root, "backup"), StageJournalRoot: filepath.Join(root, ".secret/mechanize-runtime-staging"), ArtifactJournalRoot: filepath.Join(root, ".secret/mechanize-runtime-artifacts"), NewSourceRoot: filepath.Join(root, "source"), Runtime: r}
	raw, _ := json.Marshal(p)
	if _, err := decodeMigrationInstallPlan(raw, e); err != nil {
		t.Fatal(err)
	}
	stage := f.p
	stage.options.canonicalExecutable = r.BrokerPath
	stage.oldBinarySHA256 = p.OldBrokerSHA256
	stage.newBinarySHA256 = p.BrokerCandidate.SHA256
	stage.updateConfig = e.Config.Path
	stage.updateOldInventorySHA256 = r.Artifacts[0].OldDigest
	stage.unifiedInventorySHA256 = r.Artifacts[0].NewDigest
	if _, err := newMigrationUnifiedUpdateStage(stage, r.Artifacts[0], p.ConfigCandidate.Path, e.Config.Path, p.Backup, func(context.Context) error { return nil }, func(context.Context, string, string) error { return nil }, func(context.Context, migrationStagePlan) error { return nil }, f.check); err != nil {
		t.Fatal("exact update constructor rejected", err)
	}
	changed := stage
	changed.updateConfig = filepath.Join(root, "other", "config.json")
	if migrationStageDigest(changed) == migrationStageDigest(stage) {
		t.Fatal("external config/lock path not journal-bound")
	}
	if _, err := newMigrationFileStage(stage, p.BrokerCandidate.Path, p.ConfigCandidate.Path, e.Config.Path, p.Backup, func(context.Context) error { return nil }, func(context.Context, string, string) error { return nil }, func(context.Context, migrationStagePlan) error { return nil }); err == nil {
		t.Fatal("nested broker admitted to flat file writer")
	}
	for _, mode := range []string{"nestedConfig", "newPath", "oldInventory", "helperPin", "candidateOverlap", "preinstalled"} {
		bad := p
		bad.Runtime = r
		bad.Runtime.Artifacts = append([]migrationRuntimeArtifact{}, r.Artifacts...)
		enrolled := e
		switch mode {
		case "nestedConfig":
			enrolled.Config.Path = filepath.Join(filepath.Dir(r.BrokerPath), "config.json")
		case "newPath":
			bad.Runtime.NewBrokerPath = r.BrokerPath
		case "oldInventory":
			bad.Runtime.Artifacts[0].OldDigest = strings.Repeat("f", 64)
		case "helperPin":
			bad.Runtime.ActiveHelperSHA256 = strings.Repeat("f", 64)
		case "candidateOverlap":
			bad.Runtime.Artifacts[0].Candidate = r.Artifacts[0].Target
		case "preinstalled":
			bad.Runtime.PreinstalledUnifiedApp = true
		}
		b, _ := json.Marshal(bad)
		if _, err := decodeMigrationInstallPlan(b, enrolled); err == nil {
			t.Fatal("accepted", mode)
		}
	}
}
func TestUnifiedUpdateAtomicExchangePreservesDisplacedBundleAndUnknownConfigFailure(t *testing.T) {
	for _, failConfig := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "unknown"}[failConfig], func(t *testing.T) {
			old, p, ctx := migrationFileStageFixture(t)
			root := filepath.Dir(old.config)
			target := filepath.Join(root, "Mechanize.app")
			candidate := filepath.Join(root, "candidate.app")
			for _, app := range []string{target, candidate} {
				if err := os.MkdirAll(filepath.Join(app, "Contents/Helpers"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			migrationWriteFixture(t, filepath.Join(target, "Contents/Helpers/mechanize"), "old-binary", 0700)
			migrationWriteFixture(t, filepath.Join(candidate, "Contents/Helpers/mechanize"), "new-binary", 0700)
			oi, _ := runtimeInventory(target)
			ni, _ := runtimeInventory(candidate)
			app := migrationRuntimeArtifact{Role: "unified-app", Target: target, Candidate: candidate, Old: oi, New: ni, OldDigest: runtimeInventoryDigest(oi), NewDigest: runtimeInventoryDigest(ni), OldRequirement: "old", NewRequirement: "new"}
			p.options.canonicalExecutable = filepath.Join(target, "Contents/Helpers/mechanize")
			p.updateConfig = old.config
			p.updateOldInventorySHA256 = app.OldDigest
			p.unifiedInventorySHA256 = app.NewDigest
			check, release, err := migrationPlacementLock(old.config)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			s := &migrationUnifiedStage{plan: p, candidateApp: candidate, targetApp: target, candidateConfig: old.candidateConfig, config: old.config, backup: old.backup, inventory: ni, appRequirement: "new", updateArtifact: &app, check: check, quiescent: func(context.Context) error { return nil }, complete: func(context.Context, migrationStagePlan) error { return nil }, code: func(_ context.Context, path, pin string) error {
				if failConfig && path == target && pin == "new" {
					_ = os.WriteFile(old.candidateConfig, []byte("changed"), 0600)
				}
				return nil
			}}
			if runtimeVerifyInventory(target, oi) != nil {
				t.Fatal("lock wrote inside sealed app")
			}
			err = s.place(ctx, p)
			if failConfig {
				if err != errMigrationUnknown {
					t.Fatal("uncertain config failure not retained", err)
				}
			} else {
				if err != nil || s.verifyComplete(ctx, p) != nil {
					t.Fatal("update incomplete", err)
				}
			}
			if runtimeVerifyInventory(runtimeRetainedArtifact(app, p.transitionID), oi) != nil || runtimeVerifyInventory(target, ni) != nil {
				t.Fatal("displaced/placed bundle lost")
			}
			if s.place(ctx, p) != errMigrationUnknown {
				t.Fatal("replay accepted")
			}
			backup, _ := os.ReadFile(filepath.Join(old.backup, "config.json"))
			if string(backup) != "old-config" {
				t.Fatal("config backup lost")
			}
		})
	}
}
