//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fileMigrationFixture(t *testing.T) (*fileMigrationJournal, string) {
	t.Helper()
	// macOS /var and /tmp are symlinks. Canonicalize our private fixture before
	// passing it into a journal that deliberately rejects every symlink ancestor.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, ".secret", migrationJournalDirectory)
	journal, err := newFileMigrationJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	return journal, root
}
func fileMigrationRecord() migrationJournalRecord {
	return migrationJournalRecord{state: migrationUnknown, transitionID: strings.Repeat("1", 64), optionsSHA256: strings.Repeat("2", 64), identity: []byte("public-opaque-item-fixture")}
}
func fileMigrationContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func reopenMigrationJournal(t *testing.T, root string) *fileMigrationJournal {
	t.Helper()
	journal, err := newFileMigrationJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}
func fileMigrationArtifact(t *testing.T, root, name string, bytes []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), bytes, 0o600); err != nil {
		t.Fatal(err)
	}
}
func TestFileMigrationJournalReadOnlyMissingRootNeverCreatesDirectories(t *testing.T) {
	j, root := fileMigrationFixture(t)
	if record, err := j.load(fileMigrationContext(t)); err != nil || record != nil {
		t.Fatal("missing journal not clean")
	}
	if _, err := os.Lstat(filepath.Dir(root)); !os.IsNotExist(err) {
		t.Fatal("read-only load created directories")
	}
}
func TestFileMigrationJournalUnknownAndVerifiedPersistAcrossInstances(t *testing.T) {
	j, root := fileMigrationFixture(t)
	ctx := fileMigrationContext(t)
	record := fileMigrationRecord()
	if err := j.markUnknown(ctx, record); err != nil {
		t.Fatal(err)
	}
	loaded, err := reopenMigrationJournal(t, root).load(ctx)
	if err != nil || !reflect.DeepEqual(loaded, &record) {
		t.Fatal("unknown marker not preserved")
	}
	if err = j.markVerified(ctx, record); err != nil {
		t.Fatal(err)
	}
	record.state = migrationVerified
	loaded, err = reopenMigrationJournal(t, root).load(ctx)
	if err != nil || !reflect.DeepEqual(loaded, &record) {
		t.Fatal("verified receipt not retained")
	}
	if err = j.markUnknown(ctx, fileMigrationRecord()); err == nil {
		t.Fatal("terminal receipt admitted replay")
	}
	if err = j.markVerified(ctx, fileMigrationRecord()); err == nil {
		t.Fatal("verified receipt was rewritten")
	}
	for _, path := range []string{filepath.Dir(root), root} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatal("unsafe directory mode")
		}
	}
	for _, name := range []string{"lock", "status"} {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("unsafe file mode")
		}
	}
}
func TestFileMigrationJournalCASBindsAllFieldsAndNeverClearsUnknown(t *testing.T) {
	j, _ := fileMigrationFixture(t)
	ctx := fileMigrationContext(t)
	record := fileMigrationRecord()
	if err := j.markUnknown(ctx, record); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*migrationJournalRecord){
		func(r *migrationJournalRecord) { r.transitionID = strings.Repeat("3", 64) },
		func(r *migrationJournalRecord) { r.optionsSHA256 = strings.Repeat("4", 64) },
		func(r *migrationJournalRecord) { r.identity = []byte("another-public-reference") },
		func(r *migrationJournalRecord) { r.state = migrationVerified },
	} {
		other := record
		change(&other)
		if err := j.markVerified(ctx, other); err == nil {
			t.Fatal("foreign acknowledgement accepted")
		}
	}
	if err := j.markUnknown(ctx, record); err == nil {
		t.Fatal("duplicate admission accepted")
	}
	loaded, err := j.load(ctx)
	if err != nil || !reflect.DeepEqual(loaded, &record) {
		t.Fatal("failed CAS changed original marker")
	}
}
func TestFileMigrationJournalRejectsInvalidRootOrRecordBeforeCreation(t *testing.T) {
	j, root := fileMigrationFixture(t)
	for _, bad := range []string{"relative", root + "/..", filepath.Join(filepath.Dir(root), "other"), strings.Replace(root, ".secret", "other", 1), root + "\n"} {
		if _, err := newFileMigrationJournal(bad); err == nil {
			t.Fatal("unsafe root accepted")
		}
	}
	for _, change := range []func(*migrationJournalRecord){
		func(r *migrationJournalRecord) { r.identity = nil }, func(r *migrationJournalRecord) { r.identity = make([]byte, 16385) },
		func(r *migrationJournalRecord) { r.state = migrationPreparedState }, func(r *migrationJournalRecord) { r.transitionID = "short" },
		func(r *migrationJournalRecord) { r.optionsSHA256 = strings.Repeat("F", 64) },
	} {
		record := fileMigrationRecord()
		change(&record)
		if err := j.markUnknown(fileMigrationContext(t), record); err == nil {
			t.Fatal("malformed record accepted")
		}
	}
	if _, err := os.Lstat(filepath.Dir(root)); !os.IsNotExist(err) {
		t.Fatal("invalid request created storage")
	}
}
func TestFileMigrationJournalRejectsMalformedDuplicateAndExtraJSON(t *testing.T) {
	j, root := fileMigrationFixture(t)
	ctx := fileMigrationContext(t)
	record := fileMigrationRecord()
	if err := j.markUnknown(ctx, record); err != nil {
		t.Fatal(err)
	}
	valid, err := migrationJournalEncode(record)
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{nil, []byte("{}\n"), append(bytes.Clone(valid), valid...), append([]byte(" "), valid...),
		[]byte(strings.Replace(string(valid), `"version":1`, `"version":2`, 1)),
		[]byte(strings.Replace(string(valid), `"version":1`, `"version":1,"version":1`, 1)),
		[]byte(strings.Replace(string(valid), `"version":1`, `"version":1,"extra":true`, 1)),
		[]byte(strings.Replace(string(valid), `"state":"unknown"`, `"state":"prepared"`, 1)),
		[]byte(strings.Repeat("x", migrationJournalLimit+1)),
	}
	for _, bad := range cases {
		fileMigrationArtifact(t, root, "status", bad)
		fresh := reopenMigrationJournal(t, root)
		if _, err = fresh.load(ctx); err == nil {
			t.Fatal("malformed journal became available")
		}
		if err = fresh.markUnknown(ctx, record); err == nil {
			t.Fatal("malformed journal was overwritten")
		}
	}
}
func TestFileMigrationJournalPartialStageAndUnknownArtifactsFailClosed(t *testing.T) {
	for _, name := range []string{"pending", "unexpected", "status.backup"} {
		t.Run(name, func(t *testing.T) {
			j, root := fileMigrationFixture(t)
			ctx := fileMigrationContext(t)
			record := fileMigrationRecord()
			if err := j.markUnknown(ctx, record); err != nil {
				t.Fatal(err)
			}
			fileMigrationArtifact(t, root, name, []byte("public-partial-fixture"))
			if _, err := j.load(ctx); err == nil {
				t.Fatal("unknown artifact accepted")
			}
			if err := j.markVerified(ctx, record); err == nil {
				t.Fatal("unknown artifact removed by acknowledgement")
			}
		})
	}
}
func TestFileMigrationJournalRejectsSymlinkEveryPathComponent(t *testing.T) {
	for _, which := range []string{"ancestor", "private-parent", "journal", "status", "lock"} {
		t.Run(which, func(t *testing.T) {
			j, root := fileMigrationFixture(t)
			ctx := fileMigrationContext(t)
			if err := j.markUnknown(ctx, fileMigrationRecord()); err != nil {
				t.Fatal(err)
			}
			path := root
			switch which {
			case "ancestor":
				path = filepath.Dir(filepath.Dir(root))
			case "private-parent":
				path = filepath.Dir(root)
			case "status", "lock":
				path = filepath.Join(root, which)
			}
			backup := path + "-original"
			if err := os.Rename(path, backup); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(backup, path); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(path); _ = os.Rename(backup, path) })
			if _, err := j.load(ctx); err == nil {
				t.Fatal("symlink was followed")
			}
			if err := j.markVerified(ctx, fileMigrationRecord()); err == nil {
				t.Fatal("symlink write was accepted")
			}
		})
	}
}
func TestFileMigrationJournalRejectsHardlinksAndPermissiveModes(t *testing.T) {
	for _, name := range []string{"status", "lock"} {
		t.Run("hardlink-"+name, func(t *testing.T) {
			j, root := fileMigrationFixture(t)
			ctx := fileMigrationContext(t)
			if err := j.markUnknown(ctx, fileMigrationRecord()); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(root, name), filepath.Join(filepath.Dir(filepath.Dir(root)), "public-hardlink")); err != nil {
				t.Fatal(err)
			}
			if _, err := j.load(ctx); err == nil {
				t.Fatal("hardlinked journal accepted")
			}
		})
	}
	for _, name := range []string{"parent", "directory", "status", "lock"} {
		t.Run("mode-"+name, func(t *testing.T) {
			j, root := fileMigrationFixture(t)
			ctx := fileMigrationContext(t)
			if err := j.markUnknown(ctx, fileMigrationRecord()); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, name)
			mode := os.FileMode(0o644)
			if name == "parent" {
				path = filepath.Dir(root)
				mode = 0o744
			}
			if name == "directory" {
				path = root
				mode = 0o744
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := j.load(ctx); err == nil {
				t.Fatal("permissive journal accepted")
			}
		})
	}
}
func TestFileMigrationJournalNonregularFIFORefusesPromptly(t *testing.T) {
	for _, name := range []string{"status", "lock"} {
		t.Run(name, func(t *testing.T) {
			j, root := fileMigrationFixture(t)
			ctx := fileMigrationContext(t)
			if err := j.markUnknown(ctx, fileMigrationRecord()); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := j.load(ctx); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("FIFO accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("FIFO inspection blocked")
			}
		})
	}
}
func TestFileMigrationJournalMissingOrNonemptyLockRefusesExistingRecord(t *testing.T) {
	for _, mode := range []string{"missing", "nonempty", "directory"} {
		t.Run(mode, func(t *testing.T) {
			j, root := fileMigrationFixture(t)
			ctx := fileMigrationContext(t)
			if err := j.markUnknown(ctx, fileMigrationRecord()); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "lock")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if mode == "nonempty" {
				fileMigrationArtifact(t, root, "lock", []byte("x"))
			}
			if mode == "directory" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := j.load(ctx); err == nil {
				t.Fatal("invalid lock accepted")
			}
		})
	}
}
func TestFileMigrationJournalConcurrentWritersHaveOneWinner(t *testing.T) {
	j, root := fileMigrationFixture(t)
	ctx := fileMigrationContext(t)
	// Creation races are also covered: both instances start with absent storage.
	other := reopenMigrationJournal(t, root)
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for i, writer := range []*fileMigrationJournal{j, other} {
		group.Add(1)
		go func(i int, writer *fileMigrationJournal) {
			defer group.Done()
			<-start
			record := fileMigrationRecord()
			if i == 1 {
				record.transitionID = strings.Repeat("3", 64)
			}
			results <- writer.markUnknown(ctx, record)
		}(i, writer)
	}
	close(start)
	group.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("expected one admission, got %d", wins)
	}
	loaded, err := reopenMigrationJournal(t, root).load(ctx)
	if err != nil || loaded == nil || loaded.state != migrationUnknown {
		t.Fatal("winner not durable")
	}
}
func TestFileMigrationJournalHeldFlockRefusesOtherInstance(t *testing.T) {
	j, root := fileMigrationFixture(t)
	ctx := fileMigrationContext(t)
	if err := j.markUnknown(ctx, fileMigrationRecord()); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(filepath.Join(root, "lock"), unix.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	if _, err = reopenMigrationJournal(t, root).load(ctx); err == nil {
		t.Fatal("flock exclusion bypassed")
	}
}
func TestFileMigrationJournalSyncFailuresRemainUnavailableAfterRestart(t *testing.T) {
	// Existing unknown avoids counting initial directory/lock creation syncs.
	for failAt := 1; failAt <= 3; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			j, root := fileMigrationFixture(t)
			ctx := fileMigrationContext(t)
			record := fileMigrationRecord()
			if err := j.markUnknown(ctx, record); err != nil {
				t.Fatal(err)
			}
			calls := 0
			j.synchronize = func(fd int) error {
				calls++
				if calls == failAt {
					return errors.New("private-fsync-canary")
				}
				return unix.Fsync(fd)
			}
			if err := j.markVerified(ctx, record); err != errMigrationUnavailable {
				t.Fatal("sync failure acknowledged")
			}
			if _, err := j.load(ctx); err != errMigrationUnavailable {
				t.Fatal("failed journal did not latch")
			}
			if _, err := reopenMigrationJournal(t, root).load(ctx); err != errMigrationUnavailable {
				t.Fatal("failed write lost restart barrier")
			}
		})
	}
}
func TestFileMigrationJournalRejectsCancelledUnboundedAndExpiredContexts(t *testing.T) {
	j, root := fileMigrationFixture(t)
	cancelled, cancel := context.WithCancel(fileMigrationContext(t))
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for _, ctx := range []context.Context{nil, context.Background(), cancelled, expired} {
		if _, err := j.load(ctx); err != errMigrationUnavailable {
			t.Fatal("invalid load context accepted")
		}
		if err := j.markUnknown(ctx, fileMigrationRecord()); err != errMigrationUnavailable {
			t.Fatal("invalid write context accepted")
		}
	}
	if _, err := os.Lstat(filepath.Dir(root)); !os.IsNotExist(err) {
		t.Fatal("cancelled request created storage")
	}
}
func TestFileMigrationJournalCancellationAfterWriteRetainsBarrier(t *testing.T) {
	j, root := fileMigrationFixture(t)
	ctx, cancel := context.WithCancel(fileMigrationContext(t))
	defer cancel()
	record := fileMigrationRecord()
	if err := j.markUnknown(ctx, record); err != nil {
		t.Fatal(err)
	}
	j.synchronize = func(fd int) error { err := unix.Fsync(fd); cancel(); return err }
	if err := j.markVerified(ctx, record); err != errMigrationUnavailable {
		t.Fatal("cancelled write acknowledged")
	}
	if _, err := reopenMigrationJournal(t, root).load(fileMigrationContext(t)); err != errMigrationUnavailable {
		t.Fatal("cancelled write restart barrier lost")
	}
}
func TestFileMigrationJournalWireIsBoundedPublicMetadataAndReturnedCopiesAreIndependent(t *testing.T) {
	j, root := fileMigrationFixture(t)
	ctx := fileMigrationContext(t)
	record := fileMigrationRecord()
	record.identity = bytes.Repeat([]byte{17}, 16384)
	if err := j.markUnknown(ctx, record); err != nil {
		t.Fatal(err)
	}
	record.identity[0] = 99
	loaded, err := j.load(ctx)
	if err != nil || loaded.identity[0] != 17 {
		t.Fatal("caller input aliased persisted identity")
	}
	loaded.identity[0] = 98
	second, err := j.load(ctx)
	if err != nil || second.identity[0] != 17 {
		t.Fatal("load result aliases storage")
	}
	data, err := os.ReadFile(filepath.Join(root, "status"))
	if err != nil || len(data) > migrationJournalLimit {
		t.Fatal("journal exceeded bound")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 5 {
		t.Fatal("unexpected journal fields")
	}
	text := fmt.Sprintf("%v %+v %#v", j, j, j)
	encoded, _ := json.Marshal(j)
	if strings.Contains(text+string(encoded), root) || strings.Contains(text+string(encoded), "identity") {
		t.Fatal("journal formatting exposed private storage")
	}
}
