//go:build !darwin || !cgo

package keychain

import "net"

func migrationApprovalConsolePeer(base func(*net.UnixConn) error, a *migrationApprovalConsole) func(*net.UnixConn) error {
	if a == nil {
		return base
	}
	return func(*net.UnixConn) error { return errMigrationUnavailable }
}
