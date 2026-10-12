package keychain

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func packagedFixture() migrationPackagedEnrollment {
	o := migrationFixtureOptions()
	uid := uint32(501)
	return migrationPackagedEnrollment{Version: 1, Session: strings.Repeat("a", 64), Config: migrationPackagedResource{"/fixture/private/config.json", strings.Repeat("b", 64)}, Resources: []migrationPackagedResource{{"/fixture/private/key", strings.Repeat("c", 64)}}, ConsoleRequirement: `identifier "com.viant.mechanize.consent" and cdhash H"` + strings.Repeat("d", 40) + `"`, ExpectedUID: &uid, Namespace: strings.Repeat("e", 64), ClientID: "native-console", CanonicalExecutable: o.canonicalExecutable, OldRequirement: o.oldRequirement, NewRequirement: o.newRequirement, Alias: o.alias, Service: o.item.Service, Account: o.item.Account, JournalRoot: "/fixture/.secret/mechanize-custody-migration"}
}
func encodePackaged(v migrationPackagedEnrollment) string {
	b, _ := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(b)
}
func TestMigrationPackagedEnrollmentRejectsClaimsAndAmbiguousMetadata(t *testing.T) {
	v := packagedFixture()
	if _, err := decodeMigrationPackagedEnrollment(encodePackaged(v)); err != nil {
		t.Fatal(err)
	}
	changes := []func(*migrationPackagedEnrollment){func(v *migrationPackagedEnrollment) { v.ExpectedUID = nil }, func(v *migrationPackagedEnrollment) { v.Config.Path = "relative" }, func(v *migrationPackagedEnrollment) { v.Resources = append(v.Resources, v.Resources[0]) }, func(v *migrationPackagedEnrollment) { v.Config.SHA256 = "wrong" }, func(v *migrationPackagedEnrollment) { v.Session = "" }, func(v *migrationPackagedEnrollment) { v.Resources = nil }}
	for i, change := range changes {
		v := packagedFixture()
		change(&v)
		if _, err := decodeMigrationPackagedEnrollment(encodePackaged(v)); err == nil {
			t.Errorf("invalid enrollment accepted: %d", i)
		}
	}
	raw, _ := json.Marshal(v)
	for _, invalid := range []string{string(raw[:len(raw)-1]) + `,"nativeHuman":true}`, string(raw) + `{}`, `{"version":1,"version":1}`, ""} {
		if _, err := decodeMigrationPackagedEnrollment(base64.StdEncoding.EncodeToString([]byte(invalid))); err == nil {
			t.Fatal("closed enrollment accepted wire claim")
		}
	}
}

func TestPreinstalledApprovalEnrollmentIsClosedAndSeparateFromOriginal(t *testing.T) {
	v := packagedFixture()
	v.Version = 2
	v.NewCanonicalExecutable = "/Users/fixture/Applications/Mechanize.app/Contents/Helpers/mechanize"
	v.OriginalConsoleRequirement = v.ConsoleRequirement
	v.ConsoleRequirement = `identifier "com.viant.mechanize.consent" and cdhash H"` + strings.Repeat("f", 40) + `"`
	v.ApprovalConsole = &migrationApprovalConsole{InstalledPath: "/Users/fixture/Applications/Mechanize.app", Requirement: v.ConsoleRequirement, Birth: "1800000000:2"}
	if _, err := decodeMigrationPackagedEnrollment(encodePackaged(v)); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missingOriginal", "missingApproval", "path", "pin", "birth", "version"} {
		bad := v
		a := *v.ApprovalConsole
		bad.ApprovalConsole = &a
		switch mode {
		case "missingOriginal":
			bad.OriginalConsoleRequirement = ""
		case "missingApproval":
			bad.ApprovalConsole = nil
		case "path":
			a.InstalledPath = "/foreign/Mechanize.app"
		case "pin":
			a.Requirement = v.OriginalConsoleRequirement
		case "birth":
			a.Birth = "unknown"
		case "version":
			bad.Version = 1
		}
		if _, err := decodeMigrationPackagedEnrollment(encodePackaged(bad)); err == nil {
			t.Fatal("mixed enrollment accepted", mode)
		}
	}
}
