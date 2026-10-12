//go:build linux

package keychain

import "golang.org/x/sys/unix"

func migrationExchangeNames(dir int, first, second string) error {
	return unix.Renameat2(dir, first, dir, second, unix.RENAME_EXCHANGE)
}
func migrationPublishAbsent(dir int, source, target string) error {
	return unix.Renameat2(dir, source, dir, target, unix.RENAME_NOREPLACE)
}
