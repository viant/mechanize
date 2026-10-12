package keychain

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
)

// Compiled into the signed command by the packaging tool. This closed structure
// contains custody metadata/references only, never credentials or human claims.
type migrationPackagedResource struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type migrationPackagedEnrollment struct {
	Version                    int                         `json:"version"`
	Session                    string                      `json:"session"`
	Config                     migrationPackagedResource   `json:"config"`
	Resources                  []migrationPackagedResource `json:"resources"`
	ConsoleRequirement         string                      `json:"consoleRequirement"`
	ExpectedUID                *uint32                     `json:"expectedUID"`
	Namespace                  string                      `json:"namespace"`
	ClientID                   string                      `json:"clientID"`
	CanonicalExecutable        string                      `json:"canonicalExecutable"`
	OldRequirement             string                      `json:"oldRequirement"`
	NewRequirement             string                      `json:"newRequirement"`
	Alias                      string                      `json:"alias"`
	Service                    string                      `json:"service"`
	Account                    string                      `json:"account"`
	JournalRoot                string                      `json:"journalRoot"`
	ExpectedIdentity           []byte                      `json:"expectedIdentity,omitempty"`
	Preparation                *migrationPreparationPlan   `json:"preparation,omitempty"`
	InstallPlan                *migrationPackagedResource  `json:"installPlan,omitempty"`
	NewCanonicalExecutable     string                      `json:"newCanonicalExecutable,omitempty"`
	ApprovalConsole            *migrationApprovalConsole   `json:"approvalConsole,omitempty"`
	OriginalConsoleRequirement string                      `json:"originalConsoleRequirement,omitempty"`
}

func migrationPackagedPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 4096 && !bytes.ContainsAny([]byte(path), "\x00\r\n")
}
func decodeMigrationPackagedEnrollment(encoded string) (migrationPackagedEnrollment, error) {
	var value migrationPackagedEnrollment
	if len(encoded) == 0 || len(encoded) > 65536 {
		return value, errMigrationUnavailable
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) > 49152 {
		return value, errMigrationUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return migrationPackagedEnrollment{}, errMigrationUnavailable
	}
	canonical, _ := json.Marshal(value)
	if !bytes.Equal(raw, canonical) || (value.Version != 1 && value.Version != 2 && value.Version != 3) || (value.Version == 2) != (value.NewCanonicalExecutable != "") || !validMigrationID(value.Session) || !validMigrationID(value.Namespace) || value.ClientID == "" || len(value.ClientID) > 256 || value.ExpectedUID == nil || !migrationBootstrapParentPin.MatchString(value.ConsoleRequirement) || !strings.HasPrefix(value.ConsoleRequirement, `identifier "com.viant.mechanize.consent" and cdhash H"`) || !migrationPackagedPath(value.JournalRoot) || !migrationPackagedPath(value.Config.Path) || !validMigrationID(value.Config.SHA256) || len(value.Resources) == 0 || len(value.Resources) > 16 || (value.ExpectedIdentity != nil && !validMasterIdentity(value.ExpectedIdentity)) {
		return migrationPackagedEnrollment{}, errMigrationUnavailable
	}
	if (value.ApprovalConsole == nil) != (value.OriginalConsoleRequirement == "") || value.ApprovalConsole != nil && (value.Version != 2 || !validApprovalConsole(value.ApprovalConsole, value.NewCanonicalExecutable, value.ConsoleRequirement) || !migrationBootstrapParentPin.MatchString(value.OriginalConsoleRequirement)) {
		return migrationPackagedEnrollment{}, errMigrationUnavailable
	}
	if value.Preparation != nil && (!value.Preparation.valid() || value.ExpectedIdentity != nil) {
		return migrationPackagedEnrollment{}, errMigrationUnavailable
	}
	if value.InstallPlan != nil && (value.Preparation != nil || value.ExpectedIdentity != nil || !migrationPackagedPath(value.InstallPlan.Path) || !validMigrationID(value.InstallPlan.SHA256)) {
		return migrationPackagedEnrollment{}, errMigrationUnavailable
	}
	if value.Version == 3 && !validUnifiedUpdateConfig(value.CanonicalExecutable, value.Config.Path) {
		return migrationPackagedEnrollment{}, errMigrationUnavailable
	}
	options := migrationOptions{canonicalExecutable: value.CanonicalExecutable, newCanonicalExecutable: value.NewCanonicalExecutable, oldRequirement: value.OldRequirement, newRequirement: value.NewRequirement, alias: value.Alias, item: Item{Service: value.Service, Account: value.Account}}
	if !validMigrationOptions(options) {
		return migrationPackagedEnrollment{}, errMigrationUnavailable
	}
	seen := map[string]bool{value.Config.Path: true}
	for _, resource := range value.Resources {
		if !migrationPackagedPath(resource.Path) || !validMigrationID(resource.SHA256) || seen[resource.Path] {
			return migrationPackagedEnrollment{}, errMigrationUnavailable
		}
		seen[resource.Path] = true
	}
	return value, nil
}
