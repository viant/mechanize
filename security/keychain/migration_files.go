//go:build darwin || linux

package keychain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Private installer inputs. Neither these paths nor verification callbacks may
// be supplied by the worker wire. The stage controller must sync its unknown
// journal before place. This backend does not launch a broker or edit an ACL.
type migrationFileStage struct {
	mu                                               sync.Mutex
	plan                                             migrationStagePlan
	candidateBinary, candidateConfig, config, backup string
	quiescent                                        func(context.Context) error
	code                                             func(context.Context, string, string) error
	complete                                         func(context.Context, migrationStagePlan) error
	attempted                                        bool
	borrowedCheck                                    func() error
}

// heldCheck, when supplied by the installer, borrows its full-interval lease.
// This backend checks it but never reacquires or releases that lease.
func newMigrationFileStage(p migrationStagePlan, binary, configCandidate, config, backup string,
	quiescent func(context.Context) error, code func(context.Context, string, string) error,
	complete func(context.Context, migrationStagePlan) error, heldCheck ...func() error) (*migrationFileStage, error) {
	if p.options.newCanonicalExecutable != "" || !validMigrationStagePlan(p) || quiescent == nil || code == nil || complete == nil || len(heldCheck) > 1 || len(heldCheck) == 1 && heldCheck[0] == nil {
		return nil, errMigrationUnavailable
	}
	paths := []string{p.options.canonicalExecutable, binary, configCandidate, config, backup}
	seen := map[string]bool{}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || seen[path] {
			return nil, errMigrationUnavailable
		}
		seen[path] = true
	}
	if filepath.Dir(config) != filepath.Dir(p.options.canonicalExecutable) || filepath.Base(config) != "config.json" {
		return nil, errMigrationUnavailable
	}
	p.itemIdentity = append([]byte(nil), p.itemIdentity...)
	var borrowed func() error
	if len(heldCheck) == 1 {
		borrowed = heldCheck[0]
	}
	return &migrationFileStage{borrowedCheck: borrowed, plan: p, candidateBinary: binary, candidateConfig: configCandidate, config: config, backup: backup, quiescent: quiescent, code: code, complete: complete}, nil
}

// Open every ancestor by descriptor; reject symlinks and writable foreign
// directories. The immediate parent must belong to this user and be private.
func migrationFileParent(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
		return -1, errMigrationUnavailable
	}
	dir := filepath.Dir(path)
	parts := []string{}
	for p := dir; p != "/"; p = filepath.Dir(p) {
		parts = append(parts, filepath.Base(p))
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, errMigrationUnavailable
	}
	for i := len(parts) - 1; i >= 0; i-- {
		next, e := unix.Openat(fd, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, errMigrationUnavailable
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != uint32(os.Getuid()) && st.Uid != 0) || st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0 {
			unix.Close(fd)
			return -1, errMigrationUnavailable
		}
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Getuid()) || st.Mode&0077 != 0 {
		unix.Close(fd)
		return -1, errMigrationUnavailable
	}
	return fd, nil
}

func migrationFileDigest(path string, executable bool) (string, error) {
	dir, err := migrationFileParent(path)
	if err != nil {
		return "", err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", errMigrationUnavailable
	}
	f := os.NewFile(uintptr(fd), "migration-artifact")
	defer f.Close()
	st, err := migrationArtifactRegular(fd, executable)
	if err != nil || st.Size <= 0 || st.Size > 256<<20 || executable && st.Mode&0100 == 0 || !executable && st.Mode&0111 != 0 || migrationArtifactEntry(dir, filepath.Base(path), fd, executable) != nil {
		return "", errMigrationUnavailable
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 256<<20+1))
	var after unix.Stat_t
	if err != nil || n != st.Size || unix.Fstat(fd, &after) != nil || !migrationSameFile(&st, &after) || st.Size != after.Size || migrationArtifactEntry(dir, filepath.Base(path), fd, executable) != nil || migrationFileParentMatches(path, dir) != nil {
		return "", errMigrationUnavailable
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *migrationFileStage) matches(p migrationStagePlan) bool {
	return migrationStageDigest(s.plan) == migrationStageDigest(p) && s.plan.transitionID == p.transitionID && migrationDigest(s.plan.itemIdentity) == migrationDigest(p.itemIdentity)
}
func (s *migrationFileStage) verifyBeforePlacement(ctx context.Context, p migrationStagePlan) error {
	return s.inspectCandidates(ctx, p)
}

// Read-only candidate inspection never writes installer or custody files.
func (s *migrationFileStage) inspectCandidates(ctx context.Context, p migrationStagePlan) error {
	if migrationContext(ctx) != nil || !s.matches(p) || s.quiescent(ctx) != nil || s.borrowedCheck != nil && s.borrowedCheck() != nil {
		return errMigrationUnavailable
	}
	checks := []struct {
		path, hash string
		executable bool
	}{{p.options.canonicalExecutable, p.oldBinarySHA256, true}, {s.config, p.oldConfigSHA256, false}, {s.candidateBinary, p.newBinarySHA256, true}, {s.candidateConfig, p.newConfigSHA256, false}}
	for _, check := range checks {
		sum, e := migrationFileDigest(check.path, check.executable)
		if e != nil || sum != check.hash || migrationContext(ctx) != nil {
			return errMigrationUnavailable
		}
	}
	if s.code(ctx, p.options.canonicalExecutable, p.options.oldRequirement) != nil || s.code(ctx, s.candidateBinary, p.options.newRequirement) != nil {
		return errMigrationUnavailable
	}
	return nil
}

// The caller must record unknown durably before this method. Publication swaps
// retain displaced files under deterministic transition names; no rollback occurs.
func (s *migrationFileStage) place(ctx context.Context, p migrationStagePlan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attempted || s.verifyBeforePlacement(ctx, p) != nil {
		return errMigrationUnavailable
	}
	s.attempted = true
	lock := s.borrowedCheck
	release := func() {}
	if lock == nil {
		var err error
		lock, release, err = migrationPlacementLock(p.options.canonicalExecutable)
		if err != nil {
			return errMigrationUnknown
		}
	}
	defer release() // borrowed leases are released only by the installer
	if lock() != nil {
		return errMigrationUnknown
	}
	if s.verifyBeforePlacement(ctx, p) != nil || lock() != nil {
		return errMigrationUnknown
	}
	if migrationCreateBackupDirectory(ctx, s.backup) != nil {
		return errMigrationUnknown
	}
	for _, pair := range []struct {
		source, target, digest string
		executable             bool
	}{
		{p.options.canonicalExecutable, filepath.Join(s.backup, "mechanize"), p.oldBinarySHA256, true},
		{s.config, filepath.Join(s.backup, "config.json"), p.oldConfigSHA256, false},
	} {
		if lock() != nil || migrationCopyFile(ctx, pair.source, pair.target, pair.digest, pair.executable, false) != nil {
			return errMigrationUnknown
		}
	}
	if s.quiescent(ctx) != nil || lock() != nil || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	if migrationReplaceFile(ctx, s.candidateBinary, p.options.canonicalExecutable, p.newBinarySHA256, p.oldBinarySHA256, true, p.transitionID, lock) != nil {
		return errMigrationUnknown
	}
	if s.quiescent(ctx) != nil || lock() != nil || migrationReplaceFile(ctx, s.candidateConfig, s.config, p.newConfigSHA256, p.oldConfigSHA256, false, p.transitionID, lock) != nil {
		return errMigrationUnknown
	}
	return nil
}

// Cooperating installers must share this lock; it is never removed on release.
// A malicious same-UID writer is handled by retained displaced artifacts and
// post-exchange checks, not by treating advisory flock as exclusive authority.
func migrationPlacementLock(path string) (func() error, func(), error) {
	dir, err := migrationFileParent(path)
	if err != nil {
		return nil, nil, err
	}
	const name = ".migration-placement.lock"
	fd, err := unix.Openat(dir, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err == unix.EEXIST {
		fd, err = unix.Openat(dir, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	}
	if err != nil {
		unix.Close(dir)
		return nil, nil, errMigrationUnavailable
	}
	release := func() { unix.Flock(fd, unix.LOCK_UN); unix.Close(fd); unix.Close(dir) }
	check := func() error {
		st, e := migrationArtifactRegular(fd, false)
		if e != nil || st.Size != 0 || migrationArtifactEntry(dir, name, fd, false) != nil || migrationFileParentMatches(path, dir) != nil {
			return errMigrationUnavailable
		}
		return nil
	}
	if check() != nil || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil || unix.Fsync(fd) != nil || unix.Fsync(dir) != nil {
		release()
		return nil, nil, errMigrationUnavailable
	}
	return check, release, nil
}

func migrationExchangeName(target, transition string) string {
	return ".migration-exchange-" + transition + "-" + filepath.Base(target)
}

// Preserve the actual displaced target even if it changed after the precheck.
// A mismatch after the atomic exchange is unknown, never swapped back or deleted.
func migrationReplaceFile(ctx context.Context, source, target, newHash, oldHash string, executable bool, transition string, locked func() error) error {
	if migrationContext(ctx) != nil || !validMigrationID(transition) || !validMigrationID(oldHash) || locked == nil || locked() != nil {
		return errMigrationUnavailable
	}
	current, err := migrationFileDigest(target, executable)
	if err != nil || current != oldHash {
		return errMigrationUnavailable
	}
	dir, err := migrationFileParent(target)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	old, err := unix.Openat(dir, filepath.Base(target), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return errMigrationUnavailable
	}
	defer unix.Close(old)
	if migrationArtifactEntry(dir, filepath.Base(target), old, executable) != nil {
		return errMigrationUnavailable
	}
	name := migrationExchangeName(target, transition)
	retained := filepath.Join(filepath.Dir(target), name)
	if migrationCopyFile(ctx, source, retained, newHash, executable, false) != nil {
		return errMigrationUnknown
	}
	fresh, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return errMigrationUnknown
	}
	defer unix.Close(fresh)
	if migrationArtifactEntry(dir, name, fresh, executable) != nil || migrationArtifactEntry(dir, filepath.Base(target), old, executable) != nil || migrationFileParentMatches(target, dir) != nil || locked() != nil || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	// The OS operation retains both names atomically. Unsupported filesystems fail
	// closed; there is no plain-rename or copy-overwrite fallback.
	if migrationExchangeNames(dir, name, filepath.Base(target)) != nil {
		return errMigrationUnknown
	}
	if unix.Fsync(dir) != nil || migrationArtifactEntry(dir, name, old, executable) != nil || migrationArtifactEntry(dir, filepath.Base(target), fresh, executable) != nil || migrationFileParentMatches(target, dir) != nil || locked() != nil || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	displaced, e1 := migrationFileDigest(retained, executable)
	placed, e2 := migrationFileDigest(target, executable)
	if e1 != nil || e2 != nil || displaced != oldHash || placed != newHash {
		return errMigrationUnknown
	}
	return nil
}

func migrationArtifactRegular(fd int, executable bool) (unix.Stat_t, error) {
	var st unix.Stat_t
	mode := uint32(0600)
	if executable {
		mode = 0700
	}
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || uint32(st.Mode)&07777 != mode || st.Uid != uint32(os.Getuid()) || st.Nlink != 1 {
		return st, errMigrationUnavailable
	}
	return st, nil
}

// Use this for every owned file name, including any future temporary publication
// name. A validated descriptor alone does not authenticate the name being moved.
func migrationArtifactEntry(dir int, name string, fd int, executable bool) error {
	opened, err := migrationArtifactRegular(fd, executable)
	var entry unix.Stat_t
	if err != nil || unix.Fstatat(dir, name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !migrationSameFile(&opened, &entry) {
		return errMigrationUnavailable
	}
	return nil
}
func migrationFileParentMatches(path string, fd int) error {
	current, err := migrationFileParent(path)
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

// Exclusive directory creation through a checked parent. After mkdir dispatch,
// every failure is unknown and preserves created objects for reconciliation.
func migrationCreateBackupDirectory(ctx context.Context, path string) error {
	if migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	parent, err := migrationFileParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	if migrationFileParentMatches(path, parent) != nil || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	if err = unix.Mkdirat(parent, filepath.Base(path), 0700); err != nil {
		if err == unix.EEXIST {
			return errMigrationUnavailable
		}
		return errMigrationUnknown
	}
	child, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errMigrationUnknown
	}
	defer unix.Close(child)
	var st, entry unix.Stat_t
	if unix.Fstat(child, &st) != nil || st.Uid != uint32(os.Getuid()) || st.Mode&07777 != 0700 ||
		unix.Fstatat(parent, filepath.Base(path), &entry, unix.AT_SYMLINK_NOFOLLOW) != nil || !migrationSameFile(&st, &entry) ||
		unix.Fsync(child) != nil || unix.Fsync(parent) != nil || migrationFileParentMatches(path, parent) != nil || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	return nil
}

// Only absent-target backup copies are supported. Exclusive rename atomically
// refuses an existing destination; descriptor/name identity is checked on both
// sides of publication. Temporary files are retained after any uncertainty.
// A partial new backup remains unknown, never silently deleted or rolled back.
func migrationCopyFile(ctx context.Context, source, target, digest string, executable, replace bool) error {
	if replace || migrationContext(ctx) != nil || !validMigrationID(digest) {
		return errMigrationUnavailable
	}
	sd, err := migrationFileParent(source)
	if err != nil {
		return err
	}
	defer unix.Close(sd)
	td, err := migrationFileParent(target)
	if err != nil {
		return err
	}
	defer unix.Close(td)
	sf, err := unix.Openat(sd, filepath.Base(source), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return errMigrationUnavailable
	}
	in := os.NewFile(uintptr(sf), "migration-source")
	defer in.Close()
	before, err := migrationArtifactRegular(sf, executable)
	if err != nil || before.Size <= 0 || before.Size > 256<<20 || migrationArtifactEntry(sd, filepath.Base(source), sf, executable) != nil {
		return errMigrationUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(in, (256<<20)+1))
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()
	after, check := migrationArtifactRegular(sf, executable)
	if err != nil || check != nil || !migrationSameFile(&before, &after) || before.Size != after.Size || int64(len(data)) != before.Size || migrationDigest(data) != digest ||
		migrationArtifactEntry(sd, filepath.Base(source), sf, executable) != nil || migrationFileParentMatches(source, sd) != nil || migrationFileParentMatches(target, td) != nil || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	var existing unix.Stat_t
	if unix.Fstatat(td, filepath.Base(target), &existing, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		return errMigrationUnavailable
	}
	name := ".migration-backup-" + migrationDigest([]byte(target+"\x00"+digest))
	mode := uint32(0600)
	if executable {
		mode = 0700
	}
	fd, err := unix.Openat(td, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return errMigrationUnavailable
	}
	out := os.NewFile(uintptr(fd), "migration-backup")
	defer out.Close()
	if migrationArtifactEntry(td, name, fd, executable) != nil || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	if migrationWriteAll(out, data) != nil || out.Sync() != nil || migrationArtifactEntry(td, name, fd, executable) != nil || unix.Fsync(td) != nil || migrationFileParentMatches(target, td) != nil || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	if migrationPublishAbsent(td, name, filepath.Base(target)) != nil {
		return errMigrationUnknown
	}
	if migrationArtifactEntry(td, filepath.Base(target), fd, executable) != nil || unix.Fsync(td) != nil || migrationFileParentMatches(target, td) != nil || migrationContext(ctx) != nil {
		return errMigrationUnknown
	}
	saved, err := migrationFileDigest(target, executable)
	if err != nil || saved != digest {
		return errMigrationUnknown
	}
	return nil
}

func (s *migrationFileStage) verifyComplete(ctx context.Context, p migrationStagePlan) error {
	if migrationContext(ctx) != nil || !s.matches(p) || s.quiescent(ctx) != nil || s.borrowedCheck != nil && s.borrowedCheck() != nil {
		return errMigrationUnavailable
	}
	for _, check := range []struct {
		path, hash string
		executable bool
	}{{p.options.canonicalExecutable, p.newBinarySHA256, true}, {s.config, p.newConfigSHA256, false}} {
		sum, e := migrationFileDigest(check.path, check.executable)
		if e != nil || sum != check.hash {
			return errMigrationUnavailable
		}
	}
	if s.code(ctx, p.options.canonicalExecutable, p.options.newRequirement) != nil || s.complete(ctx, p) != nil || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	return nil
}
