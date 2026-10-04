package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// Cooperating renewal processes serialize before reading the old credential.
// This does not claim atomic compare-and-swap against unrelated file writers.
func renewalLock(directory string) (func(), error) {
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return nil, errors.New("canonical credential directory required")
	}
	info, err := os.Stat(directory)
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || owner.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("owned credential directory without shared write required")
	}
	f, err := os.OpenFile(filepath.Join(directory, ".renew.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err = f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	owner, ok = info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || owner.Uid != uint32(os.Getuid()) || owner.Nlink != 1 || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("unsafe renewal lock")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("credential renewal already active")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
