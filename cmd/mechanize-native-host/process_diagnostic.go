package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/viant/mechanize/auth/nativepeer"
	"golang.org/x/sys/unix"
)

// recordProcessDiagnostic never participates in admission. The fixed directory
// derives only from the validated configuration's private socket parent. Each
// process creates one exclusive file; existing names are never replaced/followed.
func recordProcessDiagnostic(socketPath string, uid uint32, pid int, diagnostic nativepeer.ChromeLaunchDiagnostic) error {
	if !validProcessDiagnostic(diagnostic) || uid != uint32(os.Getuid()) || pid <= 1 || !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return errProcessDiagnostic
	}
	parent := filepath.Dir(socketPath)
	fd, e := openDiagnosticDirectory(parent)
	if e != nil {
		return errProcessDiagnostic
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uid || stat.Mode&07777 != 0700 {
		return errProcessDiagnostic
	}
	const name = "native-host-diagnostics"
	created := false
	if e = unix.Mkdirat(fd, name, 0700); e != nil && e != unix.EEXIST {
		return errProcessDiagnostic
	} else if e == nil {
		created = true
	}
	child, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return errProcessDiagnostic
	}
	defer unix.Close(child)
	if unix.Fstat(child, &stat) != nil || stat.Uid != uid || stat.Mode&07777 != 0700 {
		return errProcessDiagnostic
	}
	if created && unix.Fsync(fd) != nil {
		return errProcessDiagnostic
	}
	scan, e := unix.Dup(child)
	if e != nil {
		return errProcessDiagnostic
	}
	directory := os.NewFile(uintptr(scan), name)
	entries, e := directory.ReadDir(65)
	directory.Close()
	if e != nil && len(entries) == 0 && e != io.EOF {
		return errProcessDiagnostic
	}
	if len(entries) >= 64 {
		return errProcessDiagnostic
	}
	raw, e := json.Marshal(diagnostic)
	if e != nil || len(raw) > 2048 {
		return errProcessDiagnostic
	}
	filename := fmt.Sprintf("startup-%d.json", pid)
	out, e := unix.Openat(child, filename, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return errProcessDiagnostic
	}
	file := os.NewFile(uintptr(out), filename)
	defer file.Close()
	if unix.Fstat(out, &stat) != nil || stat.Uid != uid || stat.Mode&07777 != 0600 || stat.Nlink != 1 {
		return errProcessDiagnostic
	}
	if n, e := file.Write(raw); e != nil || n != len(raw) {
		return errProcessDiagnostic
	}
	if file.Sync() != nil {
		return errProcessDiagnostic
	}
	if unix.Fsync(child) != nil {
		return errProcessDiagnostic
	}
	return nil
}

var errProcessDiagnostic = fmt.Errorf("private process diagnostic unavailable")

// Walk every ancestor through directory descriptors; no intermediate symlink can
// redirect the diagnostic outside the configured private socket parent.
func openDiagnosticDirectory(path string) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, errProcessDiagnostic
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, errProcessDiagnostic
		}
		fd = next
	}
	return fd, nil
}

func validProcessDiagnostic(d nativepeer.ChromeLaunchDiagnostic) bool {
	if d.AncestryDepth < 0 || d.AncestryDepth > 16 {
		return false
	}
	switch d.ParentKind {
	case "chromeMain", "chromeHelper", "launchd", "other":
	default:
		return false
	}
	switch d.AncestryClass {
	case "unavailable", "cycle", "chromeWithinBound", "limitReached", "identityChanged":
	default:
		return false
	}
	return true
}
