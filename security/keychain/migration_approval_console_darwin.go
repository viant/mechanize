//go:build darwin && cgo

package keychain

import (
	"github.com/viant/mechanize/session"
	"golang.org/x/sys/unix"
	"net"
	"path/filepath"
)

func migrationApprovalConsolePeer(base func(*net.UnixConn) error, a *migrationApprovalConsole) func(*net.UnixConn) error {
	if a == nil {
		return base
	}
	frozen := *a
	return func(conn *net.UnixConn) error {
		if base(conn) != nil {
			return errMigrationUnavailable
		}
		raw, err := conn.SyscallConn()
		if err != nil {
			return errMigrationUnavailable
		}
		pid := 0
		var peerErr error
		if raw.Control(func(fd uintptr) { pid, peerErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID) }) != nil || peerErr != nil || pid <= 0 {
			return errMigrationUnavailable
		}
		before, alive, err := session.InspectProcess(pid)
		if err != nil || !alive || before.StartToken != frozen.Birth || before.Executable != filepath.Join(frozen.InstalledPath, "Contents/MacOS/MechanizeConsent") || !nativeReadinessPID(pid, frozen.Requirement) {
			return errMigrationUnavailable
		}
		after, alive, err := session.InspectProcess(pid)
		if err != nil || !alive || before != after || base(conn) != nil {
			return errMigrationUnavailable
		}
		return nil
	}
}
