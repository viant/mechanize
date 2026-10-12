//go:build darwin || linux

package keychain

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
)

type migrationChromeRecovery struct {
	OriginalConfig       migrationPackagedResource `json:"originalConfig"`
	OriginalChromeSHA256 string                    `json:"originalChromeSHA256"`
}

var recoveryChromeRequirement = regexp.MustCompile(`^identifier "com\.google\.Chrome" and (cdhash H"[a-f0-9]{40}"|\(cdhash H"[a-f0-9]{40}"( or cdhash H"[a-f0-9]{40}"){1,3}\))$`)
var chromeCDHashes = regexp.MustCompile(`H"[a-f0-9]{40}"`)

func exactRecoveryChromeRequirement(value string) bool {
	if !recoveryChromeRequirement.MatchString(value) {
		return false
	}
	seen := map[string]bool{}
	for _, pin := range chromeCDHashes.FindAllString(value, -1) {
		if seen[pin] {
			return false
		}
		seen[pin] = true
	}
	return true
}

func validChromeRecovery(plan migrationRuntimeArtifactPlan) bool {
	r := plan.ChromeRecovery
	return r == nil || (plan.Mode == preserveExtensionMode || unifiedRuntimeMode(plan.Mode)) && migrationPackagedPath(r.OriginalConfig.Path) && validMigrationID(r.OriginalConfig.SHA256) && validMigrationID(r.OriginalChromeSHA256) && exactRecoveryChromeRequirement(plan.ChromeRequirement)
}

// The current admin-only config must be the retained configuration with exactly
// chrome removed. Restoring scope is never inferred from a new process/pin.
func restoreReviewedChrome(old map[string]any, raw []byte, plan migrationRuntimeArtifactPlan) bool {
	r := plan.ChromeRecovery
	if r == nil || !validChromeRecovery(plan) || migrationDigest(raw) != r.OriginalConfig.SHA256 {
		return false
	}
	if _, exists := old["chrome"]; exists {
		return false
	}
	var retained map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&retained) != nil || retained == nil {
		return false
	}
	chrome, ok := retained["chrome"].(map[string]any)
	if !ok {
		return false
	}
	canonical, _ := json.Marshal(chrome)
	if migrationDigest(canonical) != r.OriginalChromeSHA256 {
		return false
	}
	trust, ok := chrome["processTrust"].(map[string]any)
	if !ok || trust["chromeExecutable"] != plan.ChromeExecutable {
		return false
	}
	oldPin, ok := trust["chromeRequirement"].(string)
	if !ok || oldPin == "" {
		return false
	}
	delete(retained, "chrome")
	expected, _ := json.Marshal(retained)
	current, _ := json.Marshal(old)
	if string(expected) != string(current) {
		return false
	}
	trust["chromeRequirement"] = plan.ChromeRequirement
	old["chrome"] = chrome
	return true
}
func applyReviewedRecordRoot(vault map[string]any, root string) bool {
	if root == "" {
		return true
	}
	home, err := migrationUserHomeDir()
	if err != nil || root != filepath.Join(home, ".secret", "vault-records") || vault["root"] != filepath.Join(home, ".secret", "vault") {
		return false
	}
	if existing, ok := vault["recordRoot"]; ok && existing != "" {
		return false
	}
	vault["recordRoot"] = root
	return true
}
