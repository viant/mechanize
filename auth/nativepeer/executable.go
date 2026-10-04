package nativepeer

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// VerifyExecutable checks a trusted exact requirement against a operator-owned
// regular executable. It does not establish the identity of a launched process;
// callers must separately authenticate its kernel audit-token socket peer.
func VerifyExecutable(path string, options Options) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.TrimSpace(options.DesignatedRequirement) == "" || strings.ContainsRune(options.DesignatedRequirement, 0) {
		return errors.New("absolute executable and enrolled code requirement required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || (owner.Uid != options.ExpectedUID && owner.Uid != 0) || owner.Nlink != 1 {
		return errors.New("unsafe enrolled executable ownership or mode")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("enrolled executable must not traverse symlinks")
	}
	return verifyExecutable(path, options)
}

// AuditPID reads the connected Unix peer's kernel audit token, never a PID
// supplied in a message. Use NewVerifier on the same connection before trust.
func AuditPID(conn *net.UnixConn) (int, error) {
	if conn == nil {
		return 0, errors.New("native peer connection required")
	}
	return auditPID(conn)
}
