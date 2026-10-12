//go:build darwin || linux

package keychain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const migrationArtifactEntries = 4096
const migrationArtifactBytes = int64(512 << 20)

type migrationRuntimeEntry struct {
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type migrationRuntimeInventory map[string]migrationRuntimeEntry

func runtimeInventoryDigest(v migrationRuntimeInventory) string {
	data, _ := json.Marshal(v)
	return migrationDigest(data)
}
func runtimeInventoryCopy(v migrationRuntimeInventory) migrationRuntimeInventory {
	r := make(migrationRuntimeInventory, len(v))
	for k, e := range v {
		r[k] = e
	}
	return r
}
func runtimeSame(a, b unix.Stat_t) bool {
	return migrationSameFile(&a, &b) && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func runtimeOwned(st unix.Stat_t) bool {
	return st.Uid == uint32(os.Getuid()) && st.Mode&0022 == 0 && st.Mode&07000 == 0
}
func runtimeArtifactParent(path string) (int, error) {
	if !migrationPackagedPath(path) || path == "/" {
		return -1, errMigrationUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, errMigrationUnavailable
	}
	for _, part := range parts {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, errMigrationUnavailable
		}
		fd = next
		var s unix.Stat_t
		if unix.Fstat(fd, &s) != nil || (s.Uid != 0 && s.Uid != uint32(os.Getuid())) || (s.Mode&0022 != 0 && s.Mode&unix.S_ISVTX == 0) {
			unix.Close(fd)
			return -1, errMigrationUnavailable
		}
	}
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || !runtimeOwned(s) {
		unix.Close(fd)
		return -1, errMigrationUnavailable
	}
	return fd, nil
}
func runtimeParentMatches(path string, fd int) error {
	current, err := runtimeArtifactParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(current)
	var a, b unix.Stat_t
	if unix.Fstat(fd, &a) != nil || unix.Fstat(current, &b) != nil || !migrationSameFile(&a, &b) {
		return errMigrationUnavailable
	}
	return nil
}
func runtimeEntryMatches(parent int, name string, fd int) error {
	var a, b unix.Stat_t
	if unix.Fstat(fd, &a) != nil || unix.Fstatat(parent, name, &b, unix.AT_SYMLINK_NOFOLLOW) != nil || !runtimeSame(a, b) {
		return errMigrationUnavailable
	}
	return nil
}
func runtimeInventory(path string) (migrationRuntimeInventory, error) {
	return runtimeInventoryBound(path, nil)
}
func runtimeInventoryBound(path string, expected migrationRuntimeInventory) (migrationRuntimeInventory, error) {
	parent, err := runtimeArtifactParent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	result := migrationRuntimeInventory{}
	var total int64
	var walk func(int, string, string) error
	walk = func(dir int, name, relative string) error {
		if len(result) >= migrationArtifactEntries {
			return errMigrationUnavailable
		}
		if expected != nil {
			if _, exists := expected[relative]; !exists {
				return errMigrationUnavailable
			}
		}
		fd, e := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if e != nil {
			return errMigrationUnavailable
		}
		file := os.NewFile(uintptr(fd), "runtime-artifact")
		defer file.Close()
		var before, after unix.Stat_t
		if unix.Fstat(fd, &before) != nil || !runtimeOwned(before) || runtimeEntryMatches(dir, name, fd) != nil {
			return errMigrationUnavailable
		}
		entry := migrationRuntimeEntry{Mode: uint32(before.Mode) & 07777}
		switch before.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			entry.Kind = "directory"
			result[relative] = entry
			names, e := file.Readdirnames(migrationArtifactEntries + 1)
			if e != nil && e != io.EOF {
				return errMigrationUnavailable
			}
			if len(names) > migrationArtifactEntries {
				return errMigrationUnavailable
			}
			sort.Strings(names)
			for _, child := range names {
				if child == "." || child == ".." || strings.ContainsAny(child, "/\x00") {
					return errMigrationUnavailable
				}
				rel := child
				if relative != "." {
					rel = relative + "/" + child
				}
				if e = walk(fd, child, rel); e != nil {
					return e
				}
			}
		case unix.S_IFREG:
			if before.Nlink != 1 || before.Size < 0 || before.Size > 256<<20 {
				return errMigrationUnavailable
			}
			entry.Kind = "file"
			entry.Size = before.Size
			total += before.Size
			if total > migrationArtifactBytes {
				return errMigrationUnavailable
			}
			hash := sha256.New()
			n, e := io.Copy(hash, io.LimitReader(file, (256<<20)+1))
			if e != nil || n != before.Size {
				return errMigrationUnavailable
			}
			entry.SHA256 = hex.EncodeToString(hash.Sum(nil))
			result[relative] = entry
		default:
			return errMigrationUnavailable
		}
		if unix.Fstat(fd, &after) != nil || !runtimeSame(before, after) || runtimeEntryMatches(dir, name, fd) != nil {
			return errMigrationUnavailable
		}
		return nil
	}
	if err = walk(parent, filepath.Base(path), "."); err != nil || runtimeParentMatches(path, parent) != nil {
		return nil, errMigrationUnavailable
	}
	return result, nil
}
func runtimeVerifyInventory(path string, want migrationRuntimeInventory) error {
	actual, err := runtimeInventoryBound(path, want)
	if err != nil || runtimeInventoryDigest(actual) != runtimeInventoryDigest(want) {
		return errMigrationUnavailable
	}
	return nil
}
func runtimeReadFile(path string, expected migrationRuntimeEntry) ([]byte, error) {
	if expected.Kind != "file" || expected.Size < 0 || expected.Size > 256<<20 || !validMigrationID(expected.SHA256) {
		return nil, errMigrationUnavailable
	}
	dir, err := runtimeArtifactParent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	f := os.NewFile(uintptr(fd), "runtime-pinned-file")
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !runtimeOwned(before) || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Size != expected.Size || uint32(before.Mode)&07777 != expected.Mode {
		return nil, errMigrationUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(f, expected.Size+1))
	if err != nil || int64(len(data)) != expected.Size || migrationDigest(data) != expected.SHA256 || unix.Fstat(fd, &after) != nil || !runtimeSame(before, after) || runtimeEntryMatches(dir, filepath.Base(path), fd) != nil || runtimeParentMatches(path, dir) != nil {
		return nil, errMigrationUnavailable
	}
	return data, nil
}
func runtimeWriteExclusive(path string, data []byte, mode uint32) error {
	dir, err := runtimeArtifactParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return errMigrationUnavailable
	}
	f := os.NewFile(uintptr(fd), "runtime-staged-file")
	defer f.Close()
	if migrationWriteAll(f, data) != nil || f.Sync() != nil || runtimeEntryMatches(dir, filepath.Base(path), fd) != nil || unix.Fsync(dir) != nil || runtimeParentMatches(path, dir) != nil {
		return errMigrationUnknown
	}
	return nil
}
func runtimeMkdirExclusive(path string, mode uint32) error {
	dir, err := runtimeArtifactParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	if unix.Mkdirat(dir, filepath.Base(path), mode) != nil {
		return errMigrationUnavailable
	}
	fd, err := unix.Openat(dir, filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errMigrationUnknown
	}
	defer unix.Close(fd)
	if runtimeEntryMatches(dir, filepath.Base(path), fd) != nil || unix.Fsync(fd) != nil || unix.Fsync(dir) != nil || runtimeParentMatches(path, dir) != nil {
		return errMigrationUnknown
	}
	return nil
}

// Copies only frozen inventory entries. Existing targets are never overwritten;
// partial trees remain for reconciliation. No config/profile/credential paths are
// enumerated or copied unless someone incorrectly includes them in signed inputs.
func runtimeCopyInventory(source, target string, inventory migrationRuntimeInventory) error {
	if runtimeVerifyInventory(source, inventory) != nil {
		return errMigrationUnavailable
	}
	keys := make([]string, 0, len(inventory))
	for key := range inventory {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entry := inventory[key]
		destination := target
		origin := source
		if key != "." {
			destination = filepath.Join(target, key)
			origin = filepath.Join(source, key)
		}
		if entry.Kind == "directory" {
			if runtimeMkdirExclusive(destination, entry.Mode) != nil {
				return errMigrationUnknown
			}
			continue
		}
		data, err := runtimeReadFile(origin, entry)
		if err != nil {
			return errMigrationUnknown
		}
		err = runtimeWriteExclusive(destination, data, entry.Mode)
		for i := range data {
			data[i] = 0
		}
		if err != nil {
			return errMigrationUnknown
		}
	}
	if runtimeVerifyInventory(source, inventory) != nil || runtimeVerifyInventory(target, inventory) != nil {
		return errMigrationUnknown
	}
	return nil
}
