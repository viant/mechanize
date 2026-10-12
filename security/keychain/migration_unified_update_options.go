package keychain

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

const unifiedAppMode = "unified-app-v2"

const unifiedUpdateMode = "unified-app-update-v3"

func unifiedRuntimeMode(mode string) bool { return mode == unifiedAppMode || mode == unifiedUpdateMode }

func validUnifiedUpdateConfig(broker, config string) bool {
	home, err := migrationUserHomeDir()
	app := filepath.Join(home, "Applications", "Mechanize.app")
	return err == nil && broker == filepath.Join(app, "Contents/Helpers/mechanize") && migrationPackagedPath(config) && filepath.Base(config) == "config.json" && !migrationPathsOverlap(config, app) && !migrationPathsOverlap(filepath.Dir(config), app)
}

// Native console workers inherit no environment. Resolve the actual process
// UID through the OS account database; never trust a caller-supplied HOME.
func migrationUserHomeDir() (string, error) {
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil || account.Uid != strconv.Itoa(os.Getuid()) || !migrationPackagedPath(account.HomeDir) || account.HomeDir == "/" {
		return "", errMigrationUnavailable
	}
	return account.HomeDir, nil
}
