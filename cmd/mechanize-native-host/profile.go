package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Chrome supplies this launch argument only when the registered manifest enables
// supports_native_initiated_connections. It is data, never an executable command.
// Call only after verifying this host's immediate signed Chrome parent.
func launchProfile(args []string, executable, origin string) (string, error) {
	if len(args) < 2 || len(args) > 4 || args[1] != origin {
		return "", errors.New("Chrome profile launch arguments unavailable")
	}
	encoded := ""
	connectID := false
	for _, arg := range args[2:] {
		if strings.HasPrefix(arg, "--reconnect-command=") && encoded == "" {
			encoded = strings.TrimPrefix(arg, "--reconnect-command=")
		} else if strings.HasPrefix(arg, "--native-messaging-connect-id=") && !connectID && len(arg) < 256 {
			connectID = true
		} else {
			return "", errors.New("unexpected Chrome launch argument")
		}
	}
	if encoded == "" || len(encoded) > 16384 {
		return "", errors.New("bounded Chrome reconnect profile evidence required")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return "", errors.New("invalid Chrome reconnect encoding")
	}
	var command []string
	if json.Unmarshal(raw, &command) != nil {
		return "", errors.New("invalid Chrome reconnect command data")
	}
	if len(command) != 7 {
		return "", errors.New("unexpected Chrome reconnect argument count")
	}
	if command[0] != executable {
		return "", errors.New("Chrome reconnect executable differs from signed parent enrollment")
	}
	values := map[string]string{}
	for _, arg := range command[1:] {
		parts := strings.SplitN(arg, "=", 2)
		if _, duplicate := values[parts[0]]; duplicate {
			return "", errors.New("duplicate Chrome reconnect argument")
		}
		value := ""
		if len(parts) == 2 {
			value = parts[1]
		}
		values[parts[0]] = value
	}
	if _, ok := values["--no-startup-window"]; !ok {
		return "", errors.New("Chrome reconnect startup fence missing")
	}
	if len(values) != 6 || values["--no-startup-window"] != "" || values["--native-messaging-connect-host"] != "com.viant.mechanize" || values["--native-messaging-connect-extension"] != strings.TrimSuffix(strings.TrimPrefix(origin, "chrome-extension://"), "/") || values["--enable-features"] != "OnConnectNative" {
		return "", errors.New("Chrome reconnect scope mismatch")
	}
	profile, root := values["--profile-directory"], values["--user-data-dir"]
	if profile == "" || profile == "." || profile == ".." || filepath.Base(profile) != profile || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("canonical Chrome profile path required")
	}
	return filepath.Join(root, profile), nil
}

func validateProfileDirectory(path string, uid uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("enrolled absolute Chrome profile directory required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("Chrome profile directory must be canonical")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errors.New("Chrome profile directory must be owned and non-writable by others")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uid {
		return errors.New("Chrome profile directory owner mismatch")
	}
	return nil
}
