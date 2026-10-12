//go:build darwin || linux

package keychain

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
)

type migrationPackagedInstallPlan struct {
	Version             int                          `json:"version"`
	OldBrokerSHA256     string                       `json:"oldBrokerSHA256"`
	BrokerCandidate     migrationPackagedResource    `json:"brokerCandidate"`
	ConfigCandidate     migrationPackagedResource    `json:"configCandidate"`
	Backup              string                       `json:"backup"`
	StageJournalRoot    string                       `json:"stageJournalRoot"`
	ArtifactJournalRoot string                       `json:"artifactJournalRoot"`
	NewSourceRoot       string                       `json:"newSourceRoot"`
	Runtime             migrationRuntimeArtifactPlan `json:"runtime"`
	Readiness           migrationKeyReadinessPlan    `json:"readiness"`
}

func decodeMigrationInstallPlan(raw []byte, enrolled migrationPackagedEnrollment) (migrationPackagedInstallPlan, error) {
	var p migrationPackagedInstallPlan
	if len(raw) == 0 || len(raw) > 1<<20 || enrolled.InstallPlan == nil {
		return p, errMigrationUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || decoder.Decode(new(any)) != io.EOF {
		return migrationPackagedInstallPlan{}, errMigrationUnavailable
	}
	canonical, _ := json.Marshal(p)
	if !bytes.Equal(raw, canonical) || (p.Version != 1 && p.Version != 2 && p.Version != 3) || p.Version != enrolled.Version || (p.Version == 2) != (p.Runtime.Mode == unifiedAppMode) || (p.Version == 3) != (p.Runtime.Mode == unifiedUpdateMode) || !validMigrationID(p.OldBrokerSHA256) || !validMigrationID(p.BrokerCandidate.SHA256) || !validMigrationID(p.ConfigCandidate.SHA256) || !migrationPackagedPath(p.BrokerCandidate.Path) || !migrationPackagedPath(p.ConfigCandidate.Path) || !migrationPackagedPath(p.Backup) || !migrationPackagedPath(p.NewSourceRoot) ||
		p.Runtime.BrokerPath != enrolled.CanonicalExecutable || p.Runtime.OldBrokerRequirement != enrolled.OldRequirement || p.Runtime.NewBrokerRequirement != enrolled.NewRequirement || (p.Version != 3 && filepath.Dir(enrolled.Config.Path) != filepath.Dir(enrolled.CanonicalExecutable)) || filepath.Base(enrolled.Config.Path) != "config.json" {
		return migrationPackagedInstallPlan{}, errMigrationUnavailable
	}
	if p.Version == 3 && (p.Runtime.ConfigPath != enrolled.Config.Path || len(p.Runtime.Artifacts) != 1 || p.OldBrokerSHA256 != p.Runtime.Artifacts[0].Old["Contents/Helpers/mechanize"].SHA256) {
		return migrationPackagedInstallPlan{}, errMigrationUnavailable
	}
	if p.Runtime.PreinstalledApprovalConsole {
		if enrolled.ApprovalConsole == nil || p.Runtime.ApprovalConsole == nil || *enrolled.ApprovalConsole != *p.Runtime.ApprovalConsole || p.Runtime.OriginalConsoleArtifact == nil || enrolled.OriginalConsoleRequirement != p.Runtime.OriginalConsoleArtifact.Requirement {
			return migrationPackagedInstallPlan{}, errMigrationUnavailable
		}
	} else if enrolled.ApprovalConsole != nil || enrolled.OriginalConsoleRequirement != "" {
		return migrationPackagedInstallPlan{}, errMigrationUnavailable
	}
	if p.Runtime.ChromeRecovery != nil && (p.Runtime.ChromeRecovery.OriginalConfig.Path == enrolled.Config.Path || p.Runtime.ChromeRecovery.OriginalConfig.Path == p.ConfigCandidate.Path) {
		return migrationPackagedInstallPlan{}, errMigrationUnavailable
	}
	if !validPreservationPlacement(p, enrolled) {
		return migrationPackagedInstallPlan{}, errMigrationUnavailable
	}
	if _, err := newRuntimeStageJournal(p.StageJournalRoot); err != nil {
		return migrationPackagedInstallPlan{}, errMigrationUnavailable
	}
	if _, err := newPrivateMigrationJournal(p.ArtifactJournalRoot, "mechanize-runtime-artifacts"); err != nil {
		return migrationPackagedInstallPlan{}, errMigrationUnavailable
	}
	return p, nil
}

// Canonical candidate config may change only the required runtime references.
// Scope flags, grants, verifier resources, master item identity, stored data and
// all other fields must remain semantically identical to the frozen old config.
func migrationInstallConfigPreserved(oldRaw, newRaw []byte, p migrationPackagedInstallPlan, enrolled migrationPackagedEnrollment, originalRecovery ...[]byte) bool {
	decode := func(raw []byte) (map[string]any, bool) {
		var value map[string]any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if d.Decode(&value) != nil || d.Decode(new(any)) != io.EOF || value == nil {
			return nil, false
		}
		return value, true
	}
	old, ok := decode(oldRaw)
	if !ok || !migrationEnrollmentMatchesConfiguration(enrolled, oldRaw) {
		return false
	}
	if p.Runtime.ChromeRecovery != nil {
		if len(originalRecovery) != 1 || !restoreReviewedChrome(old, originalRecovery[0], p.Runtime) {
			return false
		}
	} else if !preservedChromeConfigMatches(p.Runtime, old) {
		return false
	}
	next, ok := decode(newRaw)
	if !ok {
		return false
	}
	artifact := func(role string) migrationRuntimeArtifact {
		items := p.Runtime.Artifacts
		if unifiedRuntimeMode(p.Runtime.Mode) {
			items = p.Runtime.LegacyArtifacts
		}
		for _, a := range items {
			if a.Role == role {
				return a
			}
		}
		return migrationRuntimeArtifact{}
	}
	launch, ok := old["nativeLaunch"].(map[string]any)
	if !ok || old["nativeHelper"] != p.Runtime.ActiveHelperPath || launch["helperRequirement"] != p.Runtime.ActiveHelperRequirement {
		return false
	}
	old["sourceRoot"] = p.NewSourceRoot
	old["nativeHelper"] = artifact("helper").Target
	if unifiedRuntimeMode(p.Runtime.Mode) {
		destination := enrolled.NewCanonicalExecutable
		if p.Version == 3 {
			destination = enrolled.CanonicalExecutable
		}
		old["nativeHelper"] = filepath.Join(filepath.Dir(destination), "mechanize-native")
	}
	launch["helperRequirement"] = artifact("helper").NewRequirement
	console, ok := old["nativeConsole"].(map[string]any)
	if !ok {
		return false
	}
	console["designatedRequirement"] = artifact("console").NewRequirement
	vault, ok := old["nativeVault"].(map[string]any)
	if !ok {
		return false
	}
	if !applyReviewedRecordRoot(vault, p.Runtime.NativeRecordRoot) {
		return false
	}
	vault["brokerRequirement"] = enrolled.NewRequirement
	if retirement, exists := old["chromeRetirement"]; exists {
		value, ok := retirement.(map[string]any)
		if !ok {
			return false
		}
		value["brokerRequirement"] = enrolled.NewRequirement
	}
	if chrome, exists := old["chrome"]; exists {
		value, ok := chrome.(map[string]any)
		if !ok {
			return false
		}
		if trust, exists := value["processTrust"]; exists {
			process, ok := trust.(map[string]any)
			if !ok {
				return false
			}
			process["nativeHostRequirement"] = artifact("native-host").NewRequirement
			if unifiedRuntimeMode(p.Runtime.Mode) {
				destination := enrolled.NewCanonicalExecutable
				if p.Version == 3 {
					destination = enrolled.CanonicalExecutable
				}
				process["nativeHostExecutable"] = filepath.Join(filepath.Dir(destination), "mechanize-native-host")
			}
		}
	}
	expected, _ := json.Marshal(old)
	actual, _ := json.Marshal(next)
	return bytes.Equal(expected, actual)
}
