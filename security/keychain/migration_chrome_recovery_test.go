//go:build darwin || linux

package keychain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewedChromeRecoveryPreservesEveryOtherConfigurationFact(t *testing.T) {
	uid := uint32(os.Getuid())
	home, _ := os.UserHomeDir()
	enrollment := migrationPackagedEnrollment{ExpectedUID: &uid, ConsoleRequirement: "old-console", OldRequirement: "old-broker", NewRequirement: "new-broker", Alias: "master", Service: "service", Account: "account"}
	chrome := map[string]any{"processTrust": map[string]any{"chromeExecutable": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "chromeRequirement": "old-Chrome-pin", "nativeHostRequirement": "old-host"}, "grants": []any{map[string]any{"origins": []string{"https://fixture.test"}, "credentialResource": map[string]any{"URL": "/private/enrollment.sec", "Key": "unchanged-ref"}}}}
	original := map[string]any{"sourceRoot": "/old/source", "nativeHelper": "/runtime/mechanize-native", "nativeLaunch": map[string]any{"helperRequirement": "old-helper"}, "nativeConsole": map[string]any{"designatedRequirement": "old-console", "expectedUID": uid}, "nativeVault": map[string]any{"root": filepath.Join(home, ".secret", "vault"), "keyAlias": "master", "keyVersion": "unchanged-version", "brokerRequirement": "old-broker"}, "keychain": map[string]any{"Items": map[string]any{"master": map[string]any{"Service": "service", "Account": "account"}}}, "users": []string{"unchanged-user"}, "keys": map[string]any{"HMAC": map[string]any{"URL": "/private/verifier"}}, "chrome": chrome}
	retained, _ := json.Marshal(original)
	subtree, _ := json.Marshal(chrome)
	delete(original, "chrome")
	disabled, _ := json.Marshal(original)
	pin := `identifier "com.google.Chrome" and cdhash H"` + strings.Repeat("a", 40) + `"`
	plan := migrationPackagedInstallPlan{NewSourceRoot: "/new/source", Runtime: migrationRuntimeArtifactPlan{Mode: preserveExtensionMode, ChromeExecutable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", ChromeRequirement: pin, ChromeRecovery: &migrationChromeRecovery{OriginalConfig: migrationPackagedResource{Path: "/private/original-config.json", SHA256: migrationDigest(retained)}, OriginalChromeSHA256: migrationDigest(subtree)}, ActiveHelperPath: "/runtime/mechanize-native", ActiveHelperRequirement: "old-helper", NativeRecordRoot: filepath.Join(home, ".secret", "vault-records"), Artifacts: []migrationRuntimeArtifact{{Role: "helper", Target: "/runtime/mechanize-native", NewRequirement: "new-helper"}, {Role: "console", NewRequirement: "new-console"}, {Role: "native-host", NewRequirement: "new-host"}}}}
	var next map[string]any
	json.Unmarshal(retained, &next)
	next["sourceRoot"] = "/new/source"
	next["nativeLaunch"].(map[string]any)["helperRequirement"] = "new-helper"
	next["nativeConsole"].(map[string]any)["designatedRequirement"] = "new-console"
	next["nativeVault"].(map[string]any)["brokerRequirement"] = "new-broker"
	next["nativeVault"].(map[string]any)["recordRoot"] = plan.Runtime.NativeRecordRoot
	next["chrome"].(map[string]any)["processTrust"].(map[string]any)["chromeRequirement"] = pin
	next["chrome"].(map[string]any)["processTrust"].(map[string]any)["nativeHostRequirement"] = "new-host"
	candidate, _ := json.Marshal(next)
	if !migrationInstallConfigPreserved(disabled, candidate, plan, enrollment, retained) {
		t.Fatal("exact reviewed restoration refused")
	}
	relocated := plan
	relocated.Runtime.Mode = unifiedAppMode
	relocated.Runtime.LegacyArtifacts = plan.Runtime.Artifacts
	movedEnrollment := enrollment
	movedEnrollment.Version = 2
	movedEnrollment.NewCanonicalExecutable = filepath.Join(home, "Applications", "Mechanize.app", "Contents", "Helpers", "mechanize")
	var moved map[string]any
	json.Unmarshal(candidate, &moved)
	moved["nativeHelper"] = filepath.Join(filepath.Dir(movedEnrollment.NewCanonicalExecutable), "mechanize-native")
	moved["chrome"].(map[string]any)["processTrust"].(map[string]any)["nativeHostExecutable"] = filepath.Join(filepath.Dir(movedEnrollment.NewCanonicalExecutable), "mechanize-native-host")
	movedRaw, _ := json.Marshal(moved)
	if !migrationInstallConfigPreserved(disabled, movedRaw, relocated, movedEnrollment, retained) {
		t.Fatal("closed nested path relocation refused")
	}
	moved["nativeVault"].(map[string]any)["keyVersion"] = "replaced-version"
	movedRaw, _ = json.Marshal(moved)
	if migrationInstallConfigPreserved(disabled, movedRaw, relocated, movedEnrollment, retained) {
		t.Fatal("relocation changed Vault key version")
	}
	if migrationInstallConfigPreserved(disabled, candidate, plan, enrollment) {
		t.Fatal("retained source omitted")
	}
	for _, mode := range []string{"retainedDigest", "subtreeDigest", "additionalDisabledChange", "newScope", "unreviewedRecordRoot", "unreviewedRestore"} {
		t.Run(mode, func(t *testing.T) {
			modified := plan
			recovery := *plan.Runtime.ChromeRecovery
			modified.Runtime.ChromeRecovery = &recovery
			old := append([]byte{}, disabled...)
			updated := append([]byte{}, candidate...)
			switch mode {
			case "retainedDigest":
				recovery.OriginalConfig.SHA256 = strings.Repeat("b", 64)
			case "subtreeDigest":
				recovery.OriginalChromeSHA256 = strings.Repeat("b", 64)
			case "additionalDisabledChange":
				var v map[string]any
				json.Unmarshal(old, &v)
				v["users"] = []string{"changed"}
				old, _ = json.Marshal(v)
			case "newScope":
				var v map[string]any
				json.Unmarshal(updated, &v)
				v["chrome"].(map[string]any)["grants"] = []any{}
				updated, _ = json.Marshal(v)
			case "unreviewedRecordRoot":
				modified.Runtime.NativeRecordRoot = ""
			case "unreviewedRestore":
				modified.Runtime.ChromeRecovery = nil
			}
			if migrationInstallConfigPreserved(old, updated, modified, enrollment, retained) {
				t.Fatal("unreviewed recovery change accepted")
			}
		})
	}
}
func TestRecordRootTransitionCannotReplaceExistingStoreOrIdentity(t *testing.T) {
	home, _ := os.UserHomeDir()
	root := filepath.Join(home, ".secret", "vault-records")
	for _, v := range []map[string]any{{"root": "/foreign/vault"}, {"root": filepath.Join(home, ".secret", "vault"), "recordRoot": root}, {"root": filepath.Join(home, ".secret", "vault"), "recordRoot": "/other"}} {
		if applyReviewedRecordRoot(v, root) {
			t.Fatal("existing record/root replaced")
		}
	}
}
