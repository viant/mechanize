package keychain

import (
	"encoding/json"
	"testing"
)

func TestMigrationEnrollmentMatchesExistingConsoleVaultAndItem(t *testing.T) {
	uid := uint32(501)
	enrollment := migrationPackagedEnrollment{ExpectedUID: &uid, ConsoleRequirement: "exact-console", OldRequirement: "exact-old-broker", Alias: "fixture-master", Service: "com.viant.mechanize.vault", Account: "fixture-account"}
	fixture := func() map[string]any {
		return map[string]any{
			"nativeConsole": map[string]any{"expectedUID": uid, "designatedRequirement": enrollment.ConsoleRequirement},
			"nativeVault":   map[string]any{"keyAlias": enrollment.Alias, "brokerRequirement": enrollment.OldRequirement},
			"keychain":      map[string]any{"Items": map[string]any{enrollment.Alias: map[string]any{"Service": enrollment.Service, "Account": enrollment.Account}}},
		}
	}
	raw, _ := json.Marshal(fixture())
	if !migrationEnrollmentMatchesConfiguration(enrollment, raw) {
		t.Fatal("matching installation refused")
	}
	for _, change := range []string{"console", "uid", "missing-uid", "broker", "alias", "item", "missing-vault", "missing-keychain"} {
		t.Run(change, func(t *testing.T) {
			config := fixture()
			switch change {
			case "console":
				config["nativeConsole"].(map[string]any)["designatedRequirement"] = "foreign-console"
			case "uid":
				config["nativeConsole"].(map[string]any)["expectedUID"] = 502
			case "missing-uid":
				delete(config["nativeConsole"].(map[string]any), "expectedUID")
			case "broker":
				config["nativeVault"].(map[string]any)["brokerRequirement"] = "foreign-broker"
			case "alias":
				config["nativeVault"].(map[string]any)["keyAlias"] = "foreign-alias"
			case "item":
				config["keychain"].(map[string]any)["Items"].(map[string]any)[enrollment.Alias].(map[string]any)["Account"] = "foreign-account"
			case "missing-vault":
				delete(config, "nativeVault")
			case "missing-keychain":
				delete(config, "keychain")
			}
			raw, _ := json.Marshal(config)
			if migrationEnrollmentMatchesConfiguration(enrollment, raw) {
				t.Fatal("mixed enrollment admitted")
			}
		})
	}
}

func TestPreinstalledApprovalKeepsOriginalConsoleConfigAndMasterIdentity(t *testing.T) {
	uid := uint32(501)
	old := runtimeFixtureRequirement("consent", "1")
	next := runtimeFixtureRequirement("consent", "2")
	approval := &migrationApprovalConsole{InstalledPath: "/Users/fixture/Applications/Mechanize.app", Requirement: next, Birth: "1800000000:2"}
	enrolled := migrationPackagedEnrollment{Version: 2, ExpectedUID: &uid, ConsoleRequirement: next, OriginalConsoleRequirement: old, ApprovalConsole: approval, NewCanonicalExecutable: approval.InstalledPath + "/Contents/Helpers/mechanize", OldRequirement: "old-broker", Alias: "master", Service: "com.viant.mechanize.vault", Account: "same-account"}
	config := map[string]any{"nativeConsole": map[string]any{"expectedUID": uid, "designatedRequirement": old}, "nativeVault": map[string]any{"keyAlias": "master", "brokerRequirement": "old-broker"}, "keychain": map[string]any{"Items": map[string]any{"master": map[string]any{"Service": enrolled.Service, "Account": enrolled.Account}}}}
	raw, _ := json.Marshal(config)
	if !migrationEnrollmentMatchesConfiguration(enrolled, raw) {
		t.Fatal("separate approved console refused")
	}
	for _, mode := range []string{"missingApproval", "wrongOriginal", "wrongPath", "wrongItem", "version"} {
		bad := enrolled
		switch mode {
		case "missingApproval":
			bad.ApprovalConsole = nil
		case "wrongOriginal":
			bad.OriginalConsoleRequirement = next
		case "wrongPath":
			value := *approval
			value.InstalledPath = "/foreign/Mechanize.app"
			bad.ApprovalConsole = &value
		case "wrongItem":
			bad.Account = "other"
		case "version":
			bad.Version = 1
		}
		if migrationEnrollmentMatchesConfiguration(bad, raw) {
			t.Fatal("mixed approving console accepted", mode)
		}
	}
}
