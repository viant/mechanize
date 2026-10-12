package vault

import (
	"os"
	"syscall"
)

// Private ciphertext and lock files must have one directory entry and belong to
// the current user. NOFOLLOW alone rejects symlinks but permits hard links.
func privateVaultFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uint32(os.Getuid()) && owner.Nlink == 1
}
