package keychain

import (
	"path/filepath"
	"regexp"
)

type migrationApprovalConsole struct {
	InstalledPath string `json:"installedPath"`
	Requirement   string `json:"requirement"`
	Birth         string `json:"birth"`
}

func validApprovalConsole(a *migrationApprovalConsole, newBroker, requirement string) bool {
	return a != nil && migrationPackagedPath(a.InstalledPath) && filepath.Join(a.InstalledPath, "Contents/Helpers/mechanize") == newBroker && a.Requirement == requirement && migrationBootstrapParentPin.MatchString(a.Requirement) && regexp.MustCompile(`^[1-9][0-9]*:(0|[1-9][0-9]{0,5})$`).MatchString(a.Birth)
}
