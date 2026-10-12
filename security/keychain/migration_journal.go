//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const migrationJournalDirectory = "mechanize-custody-migration"
const migrationJournalLimit = 24576

// The trusted installer must supply its exact enrolled home/.secret location;
// this private constructor is not a transport/path selector. It performs no IO.
// Tests use an equivalent canonical private temporary directory hierarchy.
// Ancestors may have ordinary system permissions; the .secret and journal
// directories themselves must be owned by this user with mode exactly 0700.
func newFileMigrationJournal(root string) (*fileMigrationJournal, error) {
	return newPrivateMigrationJournal(root, migrationJournalDirectory)
}
func newRuntimeStageJournal(root string) (*fileMigrationJournal, error) {
	return newPrivateMigrationJournal(root, "mechanize-runtime-staging")
}
func newPrivateMigrationJournal(root, directory string) (*fileMigrationJournal, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || len(root) > 4096 ||
		strings.ContainsAny(root, "\x00\r\n") || filepath.Base(root) != directory ||
		filepath.Base(filepath.Dir(root)) != ".secret" {
		return nil, errMigrationUnavailable
	}
	return &fileMigrationJournal{root: root}, nil
}

type fileMigrationJournal struct {
	mu     sync.Mutex
	root   string
	failed bool
	// Test injection for descriptor synchronization only; nil uses real fsync.
	synchronize func(int) error
}

func (*fileMigrationJournal) String() string               { return "Keychain migration journal" }
func (*fileMigrationJournal) GoString() string             { return "Keychain migration journal" }
func (*fileMigrationJournal) MarshalJSON() ([]byte, error) { return []byte(`{"state":"private"}`), nil }

type migrationJournalWire struct {
	Version       int            `json:"version"`
	State         migrationState `json:"state"`
	TransitionID  string         `json:"transitionId"`
	OptionsSHA256 string         `json:"optionsSHA256"`
	Identity      []byte         `json:"identity"`
}

func migrationJournalEncode(record migrationJournalRecord) ([]byte, error) {
	if (record.state != migrationUnknown && record.state != migrationVerified) || !validMigrationID(record.transitionID) ||
		!validMigrationID(record.optionsSHA256) || !validMasterIdentity(record.identity) {
		return nil, errMigrationUnavailable
	}
	encoded, err := json.Marshal(migrationJournalWire{1, record.state, record.transitionID, record.optionsSHA256, record.identity})
	if err != nil || len(encoded)+1 > migrationJournalLimit {
		return nil, errMigrationUnavailable
	}
	return append(encoded, '\n'), nil
}
func migrationJournalDecode(data []byte) (*migrationJournalRecord, error) {
	if len(data) == 0 || len(data) > migrationJournalLimit {
		return nil, errMigrationUnavailable
	}
	var wire migrationJournalWire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || wire.Version != 1 {
		return nil, errMigrationUnavailable
	}
	record := migrationJournalRecord{state: wire.State, transitionID: wire.TransitionID, optionsSHA256: wire.OptionsSHA256, identity: wire.Identity}
	canonical, err := migrationJournalEncode(record)
	// Exact canonical form also rejects duplicate JSON keys, trailing records,
	// alternative encodings and omitted fields; decoding alone does not.
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, errMigrationUnavailable
	}
	return &record, nil
}
func migrationJournalContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errMigrationUnavailable
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return errMigrationUnavailable
	}
	return nil
}
func (j *fileMigrationJournal) sync(fd int) error {
	if j.synchronize != nil {
		return j.synchronize(fd)
	}
	return unix.Fsync(fd)
}

type migrationDirectoryLink struct {
	parent     int
	name       string
	descriptor int
	original   unix.Stat_t
}
type migrationDirectoryTree struct {
	root  int
	links []migrationDirectoryLink
}

func (t *migrationDirectoryTree) close() {
	for i := len(t.links) - 1; i >= 0; i-- {
		_ = unix.Close(t.links[i].descriptor)
	}
	if t.root >= 0 {
		_ = unix.Close(t.root)
	}
}
func migrationSameFile(a, b *unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Nlink == b.Nlink
}
func (t *migrationDirectoryTree) verify() error {
	for _, link := range t.links {
		var entry, opened unix.Stat_t
		if unix.Fstatat(link.parent, link.name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(link.descriptor, &opened) != nil ||
			(entry.Dev != opened.Dev || entry.Ino != opened.Ino || entry.Mode != opened.Mode || entry.Uid != opened.Uid) ||
			(opened.Dev != link.original.Dev || opened.Ino != link.original.Ino || opened.Mode != link.original.Mode || opened.Uid != link.original.Uid) || opened.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errMigrationUnavailable
		}
	}
	return nil
}
func (j *fileMigrationJournal) openTree(ctx context.Context, create bool) (*migrationDirectoryTree, bool, error) {
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, false, errMigrationUnavailable
	}
	tree := &migrationDirectoryTree{root: root}
	ok := false
	defer func() {
		if !ok {
			tree.close()
		}
	}()
	parts := strings.Split(strings.TrimPrefix(j.root, "/"), "/")
	parent := root
	for i, name := range parts {
		if migrationJournalContext(ctx) != nil {
			return nil, false, errMigrationUnavailable
		}
		fd, openErr := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if openErr == unix.ENOENT && i >= len(parts)-2 {
			if !create {
				return nil, false, nil
			}
			if mkdirErr := unix.Mkdirat(parent, name, 0o700); mkdirErr != nil && mkdirErr != unix.EEXIST {
				return nil, false, errMigrationUnavailable
			}
			fd, openErr = unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if openErr == nil && j.sync(parent) != nil {
				_ = unix.Close(fd)
				return nil, false, errMigrationUnavailable
			}
		}
		if openErr != nil {
			return nil, false, errMigrationUnavailable
		}
		var info unix.Stat_t
		if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR ||
			(i >= len(parts)-2 && (info.Uid != uint32(os.Getuid()) || info.Mode&0o7777 != 0o700)) {
			_ = unix.Close(fd)
			return nil, false, errMigrationUnavailable
		}
		tree.links = append(tree.links, migrationDirectoryLink{parent, name, fd, info})
		parent = fd
	}
	if tree.verify() != nil {
		return nil, false, errMigrationUnavailable
	}
	ok = true
	return tree, true, nil
}
func migrationRegular(fd int) (unix.Stat_t, error) {
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&0o7777 != 0o600 ||
		info.Uid != uint32(os.Getuid()) || info.Nlink != 1 {
		return info, errMigrationUnavailable
	}
	return info, nil
}
func migrationVerifyEntry(directory int, name string, fd int) error {
	opened, err := migrationRegular(fd)
	var entry unix.Stat_t
	if err != nil || unix.Fstatat(directory, name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !migrationSameFile(&opened, &entry) {
		return errMigrationUnavailable
	}
	return nil
}
func migrationArtifacts(directory int) (map[string]bool, error) {
	// A fresh open file description avoids sharing directory iteration offsets.
	fd, err := unix.Openat(directory, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	file := os.NewFile(uintptr(fd), "migration-journal-directory")
	defer file.Close()
	names, err := file.Readdirnames(4)
	if err != nil && err != io.EOF {
		return nil, errMigrationUnavailable
	}
	result := make(map[string]bool)
	for _, name := range names {
		if name != "lock" && name != "status" {
			return nil, errMigrationUnavailable
		}
		result[name] = true
	}
	return result, nil
}
func migrationReadRecord(directory int) (*migrationJournalRecord, error) {
	fd, err := unix.Openat(directory, "status", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err == unix.ENOENT {
		return nil, nil
	}
	if err != nil {
		return nil, errMigrationUnavailable
	}
	file := os.NewFile(uintptr(fd), "migration-journal-status")
	defer file.Close()
	info, err := migrationRegular(fd)
	if err != nil || info.Size <= 0 || info.Size > migrationJournalLimit || migrationVerifyEntry(directory, "status", fd) != nil {
		return nil, errMigrationUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, migrationJournalLimit+1))
	if err != nil || int64(len(data)) != info.Size || migrationVerifyEntry(directory, "status", fd) != nil {
		return nil, errMigrationUnavailable
	}
	return migrationJournalDecode(data)
}

func (j *fileMigrationJournal) load(ctx context.Context) (*migrationJournalRecord, error) {
	return j.access(ctx, false, nil)
}
func (j *fileMigrationJournal) markUnknown(ctx context.Context, record migrationJournalRecord) error {
	if record.state != migrationUnknown {
		return errMigrationUnavailable
	}
	record.identity = bytes.Clone(record.identity)
	if _, err := migrationJournalEncode(record); err != nil {
		return errMigrationUnavailable
	}
	_, err := j.access(ctx, true, func(previous *migrationJournalRecord) (migrationJournalRecord, error) {
		if previous != nil {
			return migrationJournalRecord{}, errMigrationUnavailable
		}
		return record, nil
	})
	return err
}
func (j *fileMigrationJournal) markVerified(ctx context.Context, record migrationJournalRecord) error {
	if record.state != migrationUnknown {
		return errMigrationUnavailable
	}
	record.identity = bytes.Clone(record.identity)
	if _, err := migrationJournalEncode(record); err != nil {
		return errMigrationUnavailable
	}
	_, err := j.access(ctx, true, func(previous *migrationJournalRecord) (migrationJournalRecord, error) {
		if previous == nil || previous.state != migrationUnknown || previous.transitionID != record.transitionID ||
			previous.optionsSHA256 != record.optionsSHA256 || !bytes.Equal(previous.identity, record.identity) {
			return migrationJournalRecord{}, errMigrationUnavailable
		}
		record.state = migrationVerified
		return record, nil
	})
	return err
}
func (j *fileMigrationJournal) access(ctx context.Context, create bool, transform func(*migrationJournalRecord) (migrationJournalRecord, error)) (*migrationJournalRecord, error) {
	if j == nil || migrationJournalContext(ctx) != nil {
		return nil, errMigrationUnavailable
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed || migrationJournalContext(ctx) != nil {
		return nil, errMigrationUnavailable
	}
	tree, exists, err := j.openTree(ctx, create)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	if !exists {
		return nil, nil
	}
	defer tree.close()
	directory := tree.links[len(tree.links)-1].descriptor
	artifacts, err := migrationArtifacts(directory)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	lockFD, err := unix.Openat(directory, "lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	createdLock := false
	if err == unix.ENOENT {
		if len(artifacts) != 0 {
			return nil, errMigrationUnavailable
		}
		if !create {
			return nil, nil
		}
		lockFD, err = unix.Openat(directory, "lock", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
		createdLock = err == nil
		if err == unix.EEXIST {
			lockFD, err = unix.Openat(directory, "lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		}
	}
	if err != nil {
		return nil, errMigrationUnavailable
	}
	defer unix.Close(lockFD)
	info, err := migrationRegular(lockFD)
	if err != nil || info.Size != 0 || unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, errMigrationUnavailable
	}
	defer unix.Flock(lockFD, unix.LOCK_UN)
	if tree.verify() != nil || migrationVerifyEntry(directory, "lock", lockFD) != nil {
		return nil, errMigrationUnavailable
	}
	if _, err = migrationArtifacts(directory); err != nil {
		return nil, errMigrationUnavailable
	}
	if createdLock && (j.sync(lockFD) != nil || j.sync(directory) != nil) {
		j.poison(directory)
		return nil, errMigrationUnavailable
	}
	previous, err := migrationReadRecord(directory)
	if err != nil || migrationJournalContext(ctx) != nil {
		return nil, errMigrationUnavailable
	}
	if transform == nil {
		if tree.verify() != nil || migrationVerifyEntry(directory, "lock", lockFD) != nil {
			return nil, errMigrationUnavailable
		}
		return previous, nil
	}
	next, err := transform(previous)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	encoded, err := migrationJournalEncode(next)
	if err != nil {
		return nil, errMigrationUnavailable
	}
	if tree.verify() != nil || migrationVerifyEntry(directory, "lock", lockFD) != nil || migrationJournalContext(ctx) != nil {
		return nil, errMigrationUnavailable
	}
	if err = j.write(ctx, directory, encoded); err != nil {
		return nil, errMigrationUnavailable
	}
	if tree.verify() != nil || migrationVerifyEntry(directory, "lock", lockFD) != nil || migrationJournalContext(ctx) != nil {
		j.poison(directory)
		return nil, errMigrationUnavailable
	}
	return &next, nil
}

// Retain an explicit failed-write artifact after a publication/sync failure.
// This is best effort: no software can promise persistence when the storage
// device refuses every write. The current instance remains permanently blocked.
func (j *fileMigrationJournal) poison(directory int) {
	j.failed = true
	fd, err := unix.Openat(directory, "pending", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err == nil {
		_, _ = unix.Write(fd, []byte("unavailable\n"))
		_ = unix.Fsync(fd)
		_ = unix.Close(fd)
	}
	_ = unix.Fsync(directory)
}
func (j *fileMigrationJournal) write(ctx context.Context, directory int, encoded []byte) (result error) {
	fd, err := unix.Openat(directory, "pending", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return errMigrationUnavailable
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		if result != nil {
			j.poison(directory)
		}
	}()
	if _, err = migrationRegular(fd); err != nil {
		return errMigrationUnavailable
	}
	remaining := encoded
	for len(remaining) > 0 {
		if migrationJournalContext(ctx) != nil {
			return errMigrationUnavailable
		}
		n, writeErr := unix.Write(fd, remaining)
		if writeErr == unix.EINTR {
			continue
		}
		if writeErr != nil || n <= 0 {
			return errMigrationUnavailable
		}
		remaining = remaining[n:]
	}
	if j.sync(fd) != nil || j.sync(directory) != nil || migrationVerifyEntry(directory, "pending", fd) != nil || migrationJournalContext(ctx) != nil {
		return errMigrationUnavailable
	}
	if unix.Renameat(directory, "pending", directory, "status") != nil || j.sync(directory) != nil || migrationVerifyEntry(directory, "status", fd) != nil || migrationJournalContext(ctx) != nil {
		return errMigrationUnavailable
	}
	if err = unix.Close(fd); err != nil {
		fd = -1
		return errMigrationUnavailable
	}
	fd = -1
	return nil
}
