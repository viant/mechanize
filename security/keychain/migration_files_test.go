//go:build darwin || linux

package keychain

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func migrationFilesRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}
func migrationWriteFixture(t *testing.T, path, value string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), mode); err != nil {
		t.Fatal(err)
	}
}
func migrationReadFixture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestMigrationArtifactModesNamesAndTypes(t *testing.T) {
	root := migrationFilesRoot(t)
	for _, tt := range []struct {
		name              string
		mode              os.FileMode
		executable, valid bool
	}{{"binary", 0700, true, true}, {"config", 0600, false, true}, {"noexecute", 0600, true, false}, {"execconfig", 0700, false, false}, {"public", 0644, false, false}} {
		path := filepath.Join(root, tt.name)
		migrationWriteFixture(t, path, "synthetic", tt.mode)
		_, err := migrationFileDigest(path, tt.executable)
		if (err == nil) != tt.valid {
			t.Fatalf("mode %s accepted=%v", tt.name, err == nil)
		}
	}
	if _, err := migrationFileDigest("relative", false); err == nil {
		t.Fatal("relative path admitted")
	}
	original := filepath.Join(root, "config")
	if err := os.Symlink(original, filepath.Join(root, "symlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := migrationFileDigest(filepath.Join(root, "symlink"), false); err == nil {
		t.Fatal("symlink admitted")
	}
	if err := os.Link(original, filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := migrationFileDigest(original, false); err == nil {
		t.Fatal("multiply linked source admitted")
	}
}
func TestMigrationArtifactTemporaryNameMustMatchDescriptor(t *testing.T) {
	root := migrationFilesRoot(t)
	path := filepath.Join(root, "temporary")
	migrationWriteFixture(t, path, "owned", 0600)
	dir, err := migrationFileParent(path)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	other := filepath.Join(root, "other")
	migrationWriteFixture(t, other, "replacement", 0600)
	if err = os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
	if migrationArtifactEntry(dir, "temporary", fd, false) == nil {
		t.Fatal("substituted name admitted")
	}
	if migrationReadFixture(t, path) != "replacement" {
		t.Fatal("validator mutated replacement")
	}
}
func TestMigrationBackupDirectoryAndExclusivePublication(t *testing.T) {
	root := migrationFilesRoot(t)
	ctx := migrationFixtureContext(t, true)
	backup := filepath.Join(root, "backup")
	if err := migrationCreateBackupDirectory(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if err := migrationCreateBackupDirectory(ctx, backup); err != errMigrationUnavailable {
		t.Fatal("existing backup directory reused")
	}
	source := filepath.Join(root, "source")
	migrationWriteFixture(t, source, "source-value", 0700)
	target := filepath.Join(backup, "binary")
	if err := migrationCopyFile(ctx, source, target, migrationDigest([]byte("source-value")), true, false); err != nil {
		t.Fatal(err)
	}
	if migrationReadFixture(t, target) != "source-value" {
		t.Fatal("backup mismatch")
	}
	if err := migrationCopyFile(ctx, source, target, migrationDigest([]byte("source-value")), true, false); err != errMigrationUnavailable {
		t.Fatal("existing target overwrite not refused")
	}
	if err := migrationCopyFile(ctx, source, target, migrationDigest([]byte("source-value")), true, true); err != errMigrationUnavailable {
		t.Fatal("unconditional overwrite admitted")
	}
	bad := filepath.Join(backup, "bad")
	if err := migrationCopyFile(ctx, source, bad, strings.Repeat("0", 64), true, false); err != errMigrationUnavailable {
		t.Fatal("wrong digest admitted")
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("refused copy wrote destination")
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(backup, link); err != nil {
		t.Fatal(err)
	}
	if err := migrationCreateBackupDirectory(ctx, filepath.Join(link, "nested")); err == nil {
		t.Fatal("symlink parent admitted")
	}
	if _, err := os.Stat(filepath.Join(backup, "nested")); !os.IsNotExist(err) {
		t.Fatal("refused mkdir wrote through symlink")
	}
}
func TestMigrationAtomicNoReplacePreservesBothFiles(t *testing.T) {
	root := migrationFilesRoot(t)
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	migrationWriteFixture(t, a, "candidate", 0600)
	migrationWriteFixture(t, b, "existing", 0600)
	dir, err := migrationFileParent(a)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	if migrationPublishAbsent(dir, "a", "b") == nil {
		t.Fatal("no-replace replaced existing file")
	}
	if migrationReadFixture(t, a) != "candidate" || migrationReadFixture(t, b) != "existing" {
		t.Fatal("atomic refusal lost an artifact")
	}
}
func TestMigrationFileExchangePreservesOriginalAndRejectsReplay(t *testing.T) {
	root := migrationFilesRoot(t)
	ctx := migrationFixtureContext(t, true)
	source, target := filepath.Join(root, "candidate"), filepath.Join(root, "mechanize")
	migrationWriteFixture(t, source, "new-binary", 0700)
	migrationWriteFixture(t, target, "old-binary", 0700)
	check, release, err := migrationPlacementLock(target)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, release2, err2 := migrationPlacementLock(target); err2 == nil {
		release2()
		t.Fatal("cooperating lock admitted concurrent writer")
	}
	transition := strings.Repeat("a", 64)
	if err = migrationReplaceFile(ctx, source, target, migrationDigest([]byte("new-binary")), migrationDigest([]byte("old-binary")), true, transition, check); err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(root, migrationExchangeName(target, transition))
	if migrationReadFixture(t, target) != "new-binary" || migrationReadFixture(t, displaced) != "old-binary" || migrationReadFixture(t, source) != "new-binary" {
		t.Fatal("exchange lost artifact")
	}
	if err = migrationReplaceFile(ctx, source, target, migrationDigest([]byte("new-binary")), migrationDigest([]byte("old-binary")), true, transition, check); err == nil {
		t.Fatal("exchange replay admitted")
	}
}
func TestMigrationExchangeRetainsRacedTargetAsUnknown(t *testing.T) {
	root := migrationFilesRoot(t)
	ctx := migrationFixtureContext(t, true)
	source, target := filepath.Join(root, "candidate"), filepath.Join(root, "mechanize")
	migrationWriteFixture(t, source, "new-binary", 0700)
	migrationWriteFixture(t, target, "old-binary", 0700)
	changed := filepath.Join(root, "changed")
	migrationWriteFixture(t, changed, "concurrent-edit", 0700)
	check, release, err := migrationPlacementLock(target)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	calls := 0
	race := func() error {
		calls++
		if err := check(); err != nil {
			return err
		}
		if calls == 2 {
			return os.Rename(changed, target)
		}
		return nil
	}
	transition := strings.Repeat("b", 64)
	if err = migrationReplaceFile(ctx, source, target, migrationDigest([]byte("new-binary")), migrationDigest([]byte("old-binary")), true, transition, race); err != errMigrationUnknown {
		t.Fatalf("race result=%v", err)
	}
	displaced := filepath.Join(root, migrationExchangeName(target, transition))
	if migrationReadFixture(t, displaced) != "concurrent-edit" || migrationReadFixture(t, target) != "new-binary" || migrationReadFixture(t, source) != "new-binary" {
		t.Fatal("unknown exchange deleted or rolled back retained artifact")
	}
}
func migrationFileStageFixture(t *testing.T) (*migrationFileStage, migrationStagePlan, context.Context) {
	root := migrationFilesRoot(t)
	p := stageFixturePlan()
	p.options.canonicalExecutable = filepath.Join(root, "mechanize")
	files := []struct {
		path, value string
		mode        os.FileMode
	}{{p.options.canonicalExecutable, "old-binary", 0700}, {filepath.Join(root, "config.json"), "old-config", 0600}, {filepath.Join(root, "candidate"), "new-binary", 0700}, {filepath.Join(root, "candidate-config"), "new-config", 0600}}
	for _, file := range files {
		migrationWriteFixture(t, file.path, file.value, file.mode)
	}
	p.oldBinarySHA256 = migrationDigest([]byte("old-binary"))
	p.newBinarySHA256 = migrationDigest([]byte("new-binary"))
	p.oldConfigSHA256 = migrationDigest([]byte("old-config"))
	p.newConfigSHA256 = migrationDigest([]byte("new-config"))
	stage, err := newMigrationFileStage(p, files[2].path, files[3].path, files[1].path, filepath.Join(root, "backup"), func(context.Context) error { return nil }, func(context.Context, string, string) error { return nil }, func(context.Context, migrationStagePlan) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return stage, p, migrationFixtureContext(t, true)
}
func TestMigrationFileStagePreservesBackupsAndPartialPlacement(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, p, ctx := migrationFileStageFixture(t)
		if err := s.place(ctx, p); err != nil {
			t.Fatal(err)
		}
		if migrationReadFixture(t, filepath.Join(s.backup, "mechanize")) != "old-binary" || migrationReadFixture(t, filepath.Join(s.backup, "config.json")) != "old-config" {
			t.Fatal("backups changed")
		}
		if err := s.verifyComplete(ctx, p); err != nil {
			t.Fatal(err)
		}
		if s.place(ctx, p) == nil {
			t.Fatal("placement replayed")
		}
	})
	t.Run("changed-before", func(t *testing.T) {
		s, p, ctx := migrationFileStageFixture(t)
		migrationWriteFixture(t, s.config, "user-edit", 0600)
		if s.place(ctx, p) == nil {
			t.Fatal("stale target admitted")
		}
		if migrationReadFixture(t, s.config) != "user-edit" || migrationReadFixture(t, p.options.canonicalExecutable) != "old-binary" {
			t.Fatal("refused stage wrote installation")
		}
		if _, err := os.Stat(s.backup); !os.IsNotExist(err) {
			t.Fatal("refused stage created backup")
		}
	})
	t.Run("partial", func(t *testing.T) {
		s, p, ctx := migrationFileStageFixture(t)
		calls := 0
		s.quiescent = func(context.Context) error {
			calls++
			if calls == 4 {
				migrationWriteFixture(t, s.config, "late-config-change", 0600)
			}
			return nil
		}
		if err := s.place(ctx, p); err != errMigrationUnknown {
			t.Fatalf("partial result=%v", err)
		}
		if migrationReadFixture(t, p.options.canonicalExecutable) != "new-binary" || migrationReadFixture(t, s.config) != "late-config-change" {
			t.Fatal("partial placement was rolled back or edit overwritten")
		}
		if migrationReadFixture(t, filepath.Join(filepath.Dir(s.config), migrationExchangeName(p.options.canonicalExecutable, p.transitionID))) != "old-binary" {
			t.Fatal("partial displaced binary not retained")
		}
		if s.place(ctx, p) == nil {
			t.Fatal("partial placement replayed")
		}
	})
}
