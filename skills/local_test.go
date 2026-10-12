package skills

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const localFixture = "---\nname: local-fixture\ndescription: Local navigation guide\n---\n\n# Navigation\nUse observed controls.\n"

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, "local-fixture")
	if err := os.Mkdir(folder, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "SKILL.md"), []byte(localFixture), 0600); err != nil {
		t.Fatal(err)
	}
	return root
}
func TestLocalGuideSnapshotAndConfinement(t *testing.T) {
	root := fixtureRoot(t)
	guides, err := LoadLocal(context.Background(), []string{root})
	if err != nil || len(guides) != 1 {
		t.Fatalf("load: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "local-fixture", "SKILL.md"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if guides[0].EntrypointText != localFixture || guides[0].Compiled.Metadata().Uri != "skill://local-fixture/SKILL.md" {
		t.Fatal("snapshot changed")
	}
	outside := filepath.Join(t.TempDir(), "private-value")
	if err := os.WriteFile(outside, []byte("must never be read"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "local-fixture", "reference.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLocal(context.Background(), []string{root}); err != ErrLocalSkills {
		t.Fatal("symlink accepted", err)
	}
}
func TestLocalGuideRejectsUnsafeRootAndOversize(t *testing.T) {
	root := fixtureRoot(t)
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLocal(context.Background(), []string{root}); err != ErrLocalSkills {
		t.Fatal("writable root accepted", err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "local-fixture", "large.txt"), []byte(strings.Repeat("x", 256*1024+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLocal(context.Background(), []string{root}); err != ErrLocalSkills {
		t.Fatal("oversized guide accepted", err)
	}
}
