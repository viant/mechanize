//go:build darwin

package keychain

import "golang.org/x/sys/unix"

func migrationExchangeNames(dir int, first, second string) error {
	return unix.RenameatxNp(dir, first, dir, second, unix.RENAME_SWAP)
}
func migrationPublishAbsent(dir int, source, target string) error {
	return unix.RenameatxNp(dir, source, dir, target, unix.RENAME_EXCL)
}
