package keychain

import "encoding/json"

// Match the signed transition to its digest-bound existing installation. A
// correctly signed but accidentally mixed candidate must not select another
// console, broker enrollment or master item. No credential data is returned.
func migrationEnrollmentMatchesConfiguration(enrollment migrationPackagedEnrollment, raw []byte) bool {
	var config struct {
		NativeConsole *struct {
			Requirement string  `json:"designatedRequirement"`
			UID         *uint32 `json:"expectedUID"`
		} `json:"nativeConsole"`
		NativeVault *struct {
			Alias       string `json:"keyAlias"`
			Requirement string `json:"brokerRequirement"`
		} `json:"nativeVault"`
		Keychain *Options `json:"keychain"`
	}
	if enrollment.ExpectedUID == nil || json.Unmarshal(raw, &config) != nil || config.NativeConsole == nil || config.NativeConsole.UID == nil || config.NativeVault == nil || config.Keychain == nil {
		return false
	}
	consoleRequirement := enrollment.ConsoleRequirement
	if enrollment.ApprovalConsole != nil {
		if enrollment.Version != 2 || !validApprovalConsole(enrollment.ApprovalConsole, enrollment.NewCanonicalExecutable, enrollment.ConsoleRequirement) || !migrationBootstrapParentPin.MatchString(enrollment.OriginalConsoleRequirement) {
			return false
		}
		consoleRequirement = enrollment.OriginalConsoleRequirement
	}
	item, found := config.Keychain.Items[enrollment.Alias]
	return found && config.NativeConsole.Requirement == consoleRequirement && *config.NativeConsole.UID == *enrollment.ExpectedUID &&
		config.NativeVault.Requirement == enrollment.OldRequirement && config.NativeVault.Alias == enrollment.Alias &&
		item.Service == enrollment.Service && item.Account == enrollment.Account
}
