//go:build darwin || linux

package keychain

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Mirrors scripts/extension_package.py exactly: current package resources and
// historical sets accepted only as the OLD installed snapshot.
var runtimeExtensionFiles = []string{"accessibility-provider.js", "browser-input.js", "browser.js", "cdp-transport.js", "connection-lifecycle.js", "content.js", "control-badge-metadata.js", "controller.js", "dom.js", "extension-maintenance.js", "fingerprint.js", "focused-location.js", "manifest.json", "options.html", "options.js", "playwright-relay.js", "playwright-target.js", "playwright-worker.js", "protection-scopes.js", "protocol.js", "recorder.js", "retirement.js", "secure-input.js", "setup-metadata.js", "tab-metadata.js", "worker.js"}

func runtimeValidInventory(v migrationRuntimeInventory) bool {
	if len(v) == 0 || len(v) > migrationArtifactEntries {
		return false
	}
	root, exists := v["."]
	if !exists {
		return false
	}
	var total int64
	for path, e := range v {
		if !utf8.ValidString(path) {
			return false
		}
		if path != "." && (filepath.IsAbs(path) || filepath.Clean(path) != path || path == ".." || strings.HasPrefix(path, "../") || strings.ContainsAny(path, "\\\x00\r\n")) {
			return false
		}
		if path != "." {
			parent := filepath.Dir(path)
			if v[parent].Kind != "directory" {
				return false
			}
		}
		if e.Kind == "directory" {
			if (e.Mode != 0700 && e.Mode != 0755) || e.Size != 0 || e.SHA256 != "" {
				return false
			}
		} else if e.Kind == "file" {
			if (e.Mode != 0600 && e.Mode != 0644 && e.Mode != 0700 && e.Mode != 0755) || e.Size < 0 || e.Size > 256<<20 || !validMigrationID(e.SHA256) {
				return false
			}
			total += e.Size
		} else {
			return false
		}
	}
	return total <= migrationArtifactBytes && (root.Kind == "directory" || root.Kind == "file" && len(v) == 1)
}
func runtimeExtensionContract(v migrationRuntimeInventory, old bool) (string, error) {
	if !runtimeValidInventory(v) || v["."].Kind != "directory" {
		return "", errMigrationUnavailable
	}
	hashes := map[string]string{}
	var total int64
	for path, e := range v {
		if path == "." {
			continue
		}
		if e.Kind != "file" || strings.Contains(path, "/") || e.Size > 4<<20 {
			return "", errMigrationUnavailable
		}
		hashes[path] = e.SHA256
		total += e.Size
	}
	if total > 16<<20 {
		return "", errMigrationUnavailable
	}
	match := func(skipFingerprint, skipRetirement, skipSetup, skipSecure, skipController, skipCDP, skipPlaywright, skipLifecycle, skipAccessibility bool) bool {
		if hashes["extension-maintenance.js"] != "" && (skipFingerprint || skipRetirement || skipSetup || skipSecure || skipController || skipCDP || skipPlaywright || skipLifecycle || skipAccessibility) {
			return false
		}
		size := 0
		for _, name := range runtimeExtensionFiles {
			if name == "extension-maintenance.js" && old && hashes[name] == "" {
				continue
			}
			if skipLifecycle && (name == "connection-lifecycle.js" || name == "focused-location.js" || name == "tab-metadata.js" || name == "control-badge-metadata.js" || name == "protection-scopes.js") {
				continue
			}
			if skipAccessibility && name == "accessibility-provider.js" {
				continue
			}
			if skipPlaywright && (name == "playwright-relay.js" || name == "playwright-target.js" || name == "playwright-worker.js") {
				continue
			}
			if skipCDP && (name == "browser-input.js" || name == "cdp-transport.js") {
				continue
			}
			if skipController && name == "controller.js" || skipFingerprint && name == "fingerprint.js" || skipRetirement && name == "retirement.js" || skipSetup && name == "setup-metadata.js" || skipSecure && name == "secure-input.js" {
				continue
			}
			size++
			if hashes[name] == "" {
				return false
			}
		}
		return len(hashes) == size
	}
	if !match(false, false, false, false, false, false, false, false, false) && !(old && (match(false, false, false, false, false, false, false, false, true) || match(false, false, false, false, false, false, false, true, true) || match(false, false, false, false, false, false, true, true, true) || match(false, false, false, false, false, true, true, true, true) || match(false, false, false, false, true, true, true, true, true) || match(false, false, false, true, true, true, true, true, true) || match(false, false, true, true, true, true, true, true, true) || match(false, true, true, true, true, true, true, true, true) || match(true, true, true, true, true, true, true, true, true))) {
		return "", errMigrationUnavailable
	}
	data, _ := json.Marshal(hashes)
	return migrationDigest(data), nil
}
func runtimeExtensionIdentity(path string, v migrationRuntimeInventory) (string, error) {
	data, err := runtimeReadFile(filepath.Join(path, "manifest.json"), v["manifest.json"])
	if err != nil {
		return "", err
	}
	var manifest map[string]any
	if json.Unmarshal(data, &manifest) != nil || manifest["manifest_version"] != float64(3) || manifest["options_page"] != "options.html" {
		return "", errMigrationUnavailable
	}
	background, ok := manifest["background"].(map[string]any)
	if !ok || len(background) != 2 || background["service_worker"] != "worker.js" || background["type"] != "module" {
		return "", errMigrationUnavailable
	}
	if key, exists := manifest["key"]; exists {
		value, ok := key.(string)
		if !ok || value == "" {
			return "", errMigrationUnavailable
		}
		return value, nil
	}
	return "", nil
}
func runtimeExtensionIDFromKey(key string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(bytes) == 0 {
		return "", errMigrationUnavailable
	}
	sum := sha256.Sum256(bytes)
	result := make([]byte, 32)
	for i, b := range sum[:16] {
		result[2*i] = 'a' + (b >> 4)
		result[2*i+1] = 'a' + (b & 15)
	}
	return string(result), nil
}

// Bounded XML plist reader for this repository's Python-generated signed build
// metadata. Binary/other plist representations remain unavailable, never guessed.
func runtimePlistStrings(data []byte) (map[string]string, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return nil, errMigrationUnavailable
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	var key string
	result := map[string]string{}
	seen := map[string]bool{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errMigrationUnavailable
		}
		switch t := token.(type) {
		case xml.StartElement:
			depth++
			if depth > 32 {
				return nil, errMigrationUnavailable
			}
			if depth == 1 && t.Name.Local != "plist" || depth == 2 && t.Name.Local != "dict" {
				return nil, errMigrationUnavailable
			}
			if depth == 3 && t.Name.Local == "key" {
				var value string
				if decoder.DecodeElement(&value, &t) != nil || seen[value] {
					return nil, errMigrationUnavailable
				}
				seen[value] = true
				key = value
				depth--
			} else if depth == 3 && t.Name.Local == "string" {
				var value string
				if key == "" || decoder.DecodeElement(&value, &t) != nil {
					return nil, errMigrationUnavailable
				}
				result[key] = value
				key = ""
				depth--
			} else if depth == 3 {
				if decoder.Skip() != nil {
					return nil, errMigrationUnavailable
				}
				key = ""
				depth--
			}
		case xml.EndElement:
			depth--
		}
	}
	if depth != 0 || len(result) == 0 {
		return nil, errMigrationUnavailable
	}
	return result, nil
}
func runtimeHelperBrokerPin(path string, v migrationRuntimeInventory) (string, error) {
	data, err := runtimeReadFile(path, v["."])
	if err != nil {
		return "", err
	}
	file, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return "", errMigrationUnavailable
	}
	defer file.Close()
	section := file.Section("__info_plist")
	if section == nil || section.Seg != "__TEXT" || section.Size > 1<<20 {
		return "", errMigrationUnavailable
	}
	raw, err := section.Data()
	if err != nil {
		return "", errMigrationUnavailable
	}
	values, err := runtimePlistStrings(bytes.TrimRight(raw, "\x00"))
	if err != nil {
		return "", err
	}
	return values["MechanizeBrokerRequirement"], nil
}

var runtimeBrokerPinPattern = regexp.MustCompile(`identifier "com\.viant\.mechanize\.broker" and cdhash H"[a-f0-9]{40}"`)

func runtimeHostBrokerPin(path string, v migrationRuntimeInventory) (string, error) {
	data, err := runtimeReadFile(path, v["."])
	if err != nil {
		return "", err
	}
	matches := runtimeBrokerPinPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return "", errMigrationUnavailable
	}
	first := string(matches[0])
	for _, match := range matches {
		if string(match) != first {
			return "", errMigrationUnavailable
		}
	}
	return first, nil
}
