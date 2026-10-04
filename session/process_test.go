//go:build darwin && cgo

package session

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestFenceHolderProcess(t *testing.T) {
	if os.Getenv("MECHANIZE_FENCE_FIXTURE") != "1" {
		return
	}
	file := os.NewFile(3, "fence")
	if _, err := file.Stat(); err != nil {
		os.Exit(2)
	}
	_, _ = os.Stdout.Write([]byte("ready\n"))
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = file.Close()
	os.Exit(0)
}
func TestInheritedFenceSurvivesBrokerDescriptorLoss(t *testing.T) {
	ctx, p := supervisorActor(t, "alice")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	_ = os.Chmod(directory, 0700)
	options := Options{LockPath: filepath.Join(directory, "desktop.lock"), HelperExecutable: executable}
	s, err := NewSupervisor(options)
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{AllowedBundles: []string{"fixture.app"}}
	_, err = s.Acquire(ctx, p, scope)
	if err != nil {
		t.Fatal(err)
	}
	file, err := s.FenceFile(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, executable, "-test.run=^TestFenceHolderProcess$")
	command.Env = append(os.Environ(), "MECHANIZE_FENCE_FIXTURE=1")
	command.ExtraFiles = []*os.File{file}
	stdin, _ := command.StdinPipe()
	stdout, _ := command.StdoutPipe()
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Process.Kill()
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); line != "ready\n" {
		t.Fatal("fixture did not start")
	}
	identity, alive, err := InspectProcess(command.Process.Pid)
	if err != nil || !alive || identity.StartToken == "" {
		t.Fatalf("public process identity: %+v %v", identity, err)
	}
	if err = s.AttachHelper(ctx, p, identity, func(context.Context) (CleanupReport, error) { return CleanupReport{}, errors.New("crash fixture") }); err != nil {
		t.Fatal(err)
	}
	// Simulate broker process death: close its descriptor WITHOUT unlocking.
	// The inherited open-file description in the helper must keep the lock.
	_ = s.file.Close()
	s.file = nil
	next, _ := NewSupervisor(options)
	if _, err = next.Acquire(ctx, p, scope); !errors.Is(err, ErrContended) {
		t.Fatalf("old helper lost physical input fence: %v", err)
	}
	_ = stdin.Close()
	if err = command.Wait(); err != nil {
		t.Fatal(err)
	}
	lease, err := next.Acquire(ctx, p, scope)
	if err != nil || lease.Generation != 2 {
		t.Fatalf("old-helper stop proof: %+v %v", lease, err)
	}
	_, _ = next.Close(ctx)
}
