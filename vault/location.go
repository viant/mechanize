package vault

import (
	"os"
	"path/filepath"
)

// outsideGit rejects normal checkouts and worktrees/submodules (.git files).
// A .git symlink or unreadable marker also refuses custody. This is an extra
// location guard, not protection against a user initializing Git concurrently.
func outsideGit(root string) bool {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false
	}
	for current := root; ; current = filepath.Dir(current) {
		_, err := os.Lstat(filepath.Join(current, ".git"))
		if err == nil || !os.IsNotExist(err) {
			return false
		}
		parent := filepath.Dir(current)
		if parent == current {
			return true
		}
	}
}
