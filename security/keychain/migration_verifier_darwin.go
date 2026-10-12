//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
int mechanize_migration_verify_process(int, const char *, const char *);
*/
import "C"

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
	"golang.org/x/sys/unix"
)

func validMigrationVerifierInput(path, requirement string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && len(path) <= 4096 &&
		!strings.ContainsAny(path, "\x00\r\n") && migrationWorkerExecutorPin.MatchString(requirement)
}
func migrationExecutableSame(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink &&
		a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// Pin descriptors through every ancestor with NOFOLLOW, then retain the final
// owned executable descriptor across Security.framework verification. The
// immediate artifact directory must be private owned0700. Ordinary system
// ancestors can have their normal modes; their identities are checked again.
func migrationExecutableCustody(path string) (verify func() bool, closeAll func(), err error) {
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, errMigrationUnavailable
	}
	tree := &migrationDirectoryTree{root: root}
	fileFD := -1
	cleanup := func() {
		if fileFD >= 0 {
			_ = unix.Close(fileFD)
		}
		tree.close()
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	parent := root
	for _, name := range parts[:len(parts)-1] {
		fd, openErr := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if openErr != nil {
			cleanup()
			return nil, nil, errMigrationUnavailable
		}
		var info unix.Stat_t
		if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR || (info.Uid != 0 && info.Uid != uint32(os.Getuid())) {
			_ = unix.Close(fd)
			cleanup()
			return nil, nil, errMigrationUnavailable
		}
		tree.links = append(tree.links, migrationDirectoryLink{parent: parent, name: name, descriptor: fd, original: info})
		parent = fd
	}
	if len(tree.links) == 0 {
		cleanup()
		return nil, nil, errMigrationUnavailable
	}
	directory := tree.links[len(tree.links)-1].original
	if directory.Uid != uint32(os.Getuid()) || directory.Mode&0o7777 != 0o700 {
		cleanup()
		return nil, nil, errMigrationUnavailable
	}
	name := parts[len(parts)-1]
	fileFD, err = unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		cleanup()
		return nil, nil, errMigrationUnavailable
	}
	var original unix.Stat_t
	if unix.Fstat(fileFD, &original) != nil || original.Mode&unix.S_IFMT != unix.S_IFREG || original.Uid != uint32(os.Getuid()) ||
		original.Mode&0o022 != 0 || original.Mode&0o100 == 0 || original.Mode&0o7000 != 0 || original.Nlink != 1 {
		cleanup()
		return nil, nil, errMigrationUnavailable
	}
	verify = func() bool {
		var current, entry unix.Stat_t
		return tree.verify() == nil && unix.Fstat(fileFD, &current) == nil && unix.Fstatat(parent, name, &entry, unix.AT_SYMLINK_NOFOLLOW) == nil &&
			migrationExecutableSame(original, current) && migrationExecutableSame(original, entry)
	}
	if !verify() {
		cleanup()
		return nil, nil, errMigrationUnavailable
	}
	return verify, cleanup, nil
}

// Exact worker code, file custody and existing trusted native-human authority
// are all required. Nativepeer/framework errors are intentionally closed here.
func verifyMigrationExecutable(ctx context.Context, path, requirement string) error {
	if migrationContext(ctx) != nil || !validMigrationVerifierInput(path, requirement) {
		return errMigrationUnavailable
	}
	unchanged, release, err := migrationExecutableCustody(path)
	if err != nil {
		return errMigrationUnavailable
	}
	defer release()
	if migrationContext(ctx) != nil || nativepeer.VerifyExecutable(path, nativepeer.Options{ExpectedUID: uint32(os.Getuid()), DesignatedRequirement: requirement}) != nil ||
		!unchanged() || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	return nil
}
func migrationDynamicCode(pid int, path, requirement string) bool {
	if pid <= 0 || int64(pid) > 1<<31-1 || !validMigrationVerifierInput(path, requirement) {
		return false
	}
	p, r := C.CString(path), C.CString(requirement)
	defer C.free(unsafe.Pointer(p))
	defer C.free(unsafe.Pointer(r))
	return C.mechanize_migration_verify_process(C.int(pid), p, r) == 1
}

type migrationRunningVerifier struct {
	mu                sync.Mutex
	path, requirement string
	process           *os.Process
	identity          *session.ProcessIdentity
	failed            bool
	inspect           session.ProcessInspector
	verifyCode        func(int, string, string) bool
}

func (v *migrationRunningVerifier) matches(identity session.ProcessIdentity, pid int) bool {
	return identity.PID == pid && identity.UID == uint32(os.Getuid()) && identity.Executable == v.path &&
		len(identity.StartToken) > 0 && len(identity.StartToken) <= 64 && !strings.ContainsAny(identity.StartToken, "\x00\r\n")
}
func (v *migrationRunningVerifier) verify(ctx context.Context, process *os.Process, requirement string) error {
	if migrationContext(ctx) != nil || process == nil || process.Pid <= 0 || requirement != v.requirement {
		return errMigrationUnavailable
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.failed || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	fail := func() error { v.failed = true; return errMigrationUnavailable }
	if v.process != nil && v.process != process {
		return fail()
	}
	if verifyMigrationExecutable(ctx, v.path, v.requirement) != nil {
		return fail()
	}
	before, alive, err := v.inspect(process.Pid)
	if err != nil || !alive || !v.matches(before, process.Pid) || migrationContext(ctx) != nil {
		return fail()
	}
	if v.identity != nil && *v.identity != before {
		return fail()
	}
	// Capture before the dynamic code check; later callbacks cannot silently
	// adopt a reused PID, new process object or another birth token after failure.
	if v.identity == nil {
		copy := before
		v.identity = &copy
		v.process = process
	}
	if !v.verifyCode(process.Pid, v.path, v.requirement) || migrationContext(ctx) != nil {
		return fail()
	}
	after, alive, err := v.inspect(process.Pid)
	if err != nil || !alive || !v.matches(after, process.Pid) || before != after || *v.identity != after ||
		verifyMigrationExecutable(ctx, v.path, v.requirement) != nil || migrationContext(ctx) != nil {
		return fail()
	}
	return nil
}

// Private callbacks for migrationProcessSpec, bound to one exact artifact and
// one owned child object. Construction does not launch or inspect any process.
// The first process MUST be the object returned by the trusted owned Start;
// this is not a general verifier for an arbitrary caller-supplied PID.
func migrationVerifierFactory(path, requirement string) (func(context.Context, string, string) error, func(context.Context, *os.Process, string) error, error) {
	if !validMigrationVerifierInput(path, requirement) {
		return nil, nil, errMigrationUnavailable
	}
	verifier := &migrationRunningVerifier{path: path, requirement: requirement, inspect: session.InspectProcess, verifyCode: migrationDynamicCode}
	file := func(ctx context.Context, actualPath, actualRequirement string) error {
		if actualPath != path || actualRequirement != requirement {
			return errMigrationUnavailable
		}
		return verifyMigrationExecutable(ctx, path, requirement)
	}
	return file, verifier.verify, nil
}
