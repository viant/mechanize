package main

import (
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/auth/nativepeer"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func diagnosticDirectory(t *testing.T) string {
	t.Helper()
	dir, e := os.MkdirTemp("/private/tmp", "native-diagnostic-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
func TestProcessDiagnosticPrivateExclusiveFile(t *testing.T) {
	dir := diagnosticDirectory(t)
	uid := uint32(os.Getuid())
	pid := os.Getpid()
	evidence := nativepeer.ChromeLaunchDiagnostic{HostPIDMatches: true, HostStartMatches: true, HostUIDMatches: true, ParentKind: "chromeMain", ParentPathMatchesPolicy: true, ParentUIDMatches: true, DynamicParentPinMatches: true, AncestryDepth: 1, AncestryClass: "chromeWithinBound"}
	if e := recordProcessDiagnostic(filepath.Join(dir, "broker.sock"), uid, pid, evidence); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "native-host-diagnostics", fmt.Sprintf("startup-%d.json", pid))
	raw, e := os.ReadFile(path)
	if e != nil || len(raw) > 2048 {
		t.Fatal("bounded diagnostic absent")
	}
	var actual nativepeer.ChromeLaunchDiagnostic
	if json.Unmarshal(raw, &actual) != nil || actual != evidence {
		t.Fatal("metadata changed")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("diagnostic not private")
	}
	if e = recordProcessDiagnostic(filepath.Join(dir, "broker.sock"), uid, pid, evidence); e == nil {
		t.Fatal("existing evidence overwritten")
	}
}
func TestProcessDiagnosticRefusesUnsafeCustody(t *testing.T) {
	for _, kind := range []string{"uid", "parentMode", "directorySymlink", "ancestorSymlink", "fileSymlink", "fileHardlink", "capacity"} {
		t.Run(kind, func(t *testing.T) {
			dir := diagnosticDirectory(t)
			uid := uint32(os.Getuid())
			pid := os.Getpid()
			socket := filepath.Join(dir, "broker.sock")
			child := filepath.Join(dir, "native-host-diagnostics")
			target := filepath.Join(dir, "private-canary")
			os.WriteFile(target, []byte("private-token-canary"), 0600)
			switch kind {
			case "uid":
				uid++
			case "parentMode":
				os.Chmod(dir, 0755)
			case "directorySymlink":
				os.Symlink(dir, child)
			case "ancestorSymlink":
				link := filepath.Join(dir, "link")
				os.Symlink(dir, link)
				socket = filepath.Join(link, "broker.sock")
			case "fileSymlink", "fileHardlink":
				os.Mkdir(child, 0700)
				path := filepath.Join(child, fmt.Sprintf("startup-%d.json", pid))
				if kind == "fileSymlink" {
					os.Symlink(target, path)
				} else {
					os.Link(target, path)
				}
			case "capacity":
				os.Mkdir(child, 0700)
				for i := 0; i < 64; i++ {
					os.WriteFile(filepath.Join(child, fmt.Sprintf("held-%d", i)), nil, 0600)
				}
			}
			e := recordProcessDiagnostic(socket, uid, pid, nativepeer.ChromeLaunchDiagnostic{ParentKind: "other", AncestryClass: "unavailable"})
			if e == nil || strings.Contains(e.Error(), "canary") {
				t.Fatal("unsafe diagnostic custody accepted")
			}
			raw, _ := os.ReadFile(target)
			if string(raw) != "private-token-canary" {
				t.Fatal("unrelated target modified")
			}
		})
	}
}

func TestProcessDiagnosticRejectsUnclosedMetadataBeforeWriting(t *testing.T) {
	dir := diagnosticDirectory(t)
	for _, d := range []nativepeer.ChromeLaunchDiagnostic{{ParentKind: "private-path-canary", AncestryClass: "unavailable"}, {ParentKind: "other", AncestryClass: "private-error-canary"}, {ParentKind: "other", AncestryClass: "unavailable", AncestryDepth: 17}} {
		if e := recordProcessDiagnostic(filepath.Join(dir, "broker.sock"), uint32(os.Getuid()), os.Getpid(), d); e == nil || strings.Contains(e.Error(), "canary") {
			t.Fatal("unclosed diagnostic metadata accepted")
		}
	}
	if _, e := os.Stat(filepath.Join(dir, "native-host-diagnostics")); !os.IsNotExist(e) {
		t.Fatal("invalid metadata wrote diagnostic directory")
	}
}
