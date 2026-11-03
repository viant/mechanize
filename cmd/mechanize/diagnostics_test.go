package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestDiagnosticsOptInAndCleanup(t *testing.T) {
	close, err := startDiagnostics("")
	if err != nil {
		t.Fatal(err)
	}
	close()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "private")
	close, err = startDiagnostics(dir)
	if err != nil {
		t.Fatal(err)
	}
	pidfile := filepath.Join(dir, strconv.Itoa(os.Getpid()))
	if _, err = os.Stat(pidfile); err != nil {
		close()
		t.Fatal(err)
	}
	close()
	if _, err = os.Stat(pidfile); !os.IsNotExist(err) {
		t.Fatal("diagnostic port registration not removed", err)
	}
}
func TestDiagnosticsRejectsSharedAndSymlinkDirectories(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(root, "shared")
	if err = os.Mkdir(shared, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = startDiagnostics(shared); err == nil {
		t.Fatal("shared directory accepted")
	}
	private := filepath.Join(root, "private")
	if err = os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err = os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if _, err = startDiagnostics(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err = startDiagnostics("relative"); err == nil {
		t.Fatal("relative directory accepted")
	}
}
