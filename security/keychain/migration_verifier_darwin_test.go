//go:build darwin && cgo

package keychain

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/viant/mechanize/session"
	"golang.org/x/sys/unix"
)

// Public disposable fixture only. Its sole behavior is pipe readiness/ping and
// waiting for stdin. It does not link Security.framework or call Keychain/UI.
func migrationVerifierFixture(t *testing.T) (string, string) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	source, binary := filepath.Join(directory, "public.c"), filepath.Join(directory, "public-worker")
	program := `#include <unistd.h>
int main(void) { char input; if (write(1,"R",1)!=1) return 1; while (read(0,&input,1)==1) { if (input=='q') return 0; if (write(1,"P",1)!=1) return 2; } return 0; }
`
	if err = os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "clang", source, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("public fixture compilation failed: %v: %s", err, output)
	}
	if output, err := exec.CommandContext(ctx, "codesign", "--force", "--sign", "-", "--identifier", "com.viant.mechanize.custody-migration", binary).CombinedOutput(); err != nil {
		t.Fatalf("public fixture signing failed: %v: %s", err, output)
	}
	output, err := exec.CommandContext(ctx, "codesign", "--display", "--verbose=4", binary).CombinedOutput()
	if err != nil {
		t.Fatal("public fixture signature unavailable")
	}
	match := regexp.MustCompile(`(?m)^CDHash=([0-9a-f]{40})$`).FindSubmatch(output)
	if len(match) != 2 {
		t.Fatal("public fixture has no exact hash")
	}
	rule := `identifier "com.viant.mechanize.custody-migration" and cdhash H"` + string(match[1]) + `"`
	return binary, rule
}
func startMigrationVerifierFixture(t *testing.T, path string) (*os.Process, func()) {
	t.Helper()
	command := exec.Command(path)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { _ = input.Close(); _ = command.Process.Kill(); _ = command.Wait() }) }
	t.Cleanup(stop)
	ready := make(chan bool, 1)
	go func() {
		var byte [1]byte
		_, err := io.ReadFull(output, byte[:])
		ready <- err == nil && byte[0] == 'R'
	}()
	select {
	case ok := <-ready:
		if !ok {
			stop()
			t.Fatal("owned fixture not ready")
		}
	case <-time.After(5 * time.Second):
		stop()
		t.Fatal("owned fixture readiness timeout")
	}
	return command.Process, stop
}
func TestMigrationExecutableStaticAndOwnedDynamicExactPins(t *testing.T) {
	path, rule := migrationVerifierFixture(t)
	ctx := migrationFixtureContext(t, true)
	file, running, err := migrationVerifierFactory(path, rule)
	if err != nil {
		t.Fatal(err)
	}
	if err = file(ctx, path, rule); err != nil {
		t.Fatal("exact public static fixture refused")
	}
	process, _ := startMigrationVerifierFixture(t, path)
	if err = running(ctx, process, rule); err != nil {
		t.Fatal("exact owned running fixture refused")
	}
	if err = running(ctx, process, rule); err != nil {
		t.Fatal("unchanged process birth refused")
	}
	wrongPin := `identifier "com.viant.mechanize.custody-migration" and cdhash H"` + strings.Repeat("0", 40) + `"`
	if migrationDynamicCode(process.Pid, path, wrongPin) || migrationDynamicCode(process.Pid, path+"-other", rule) {
		t.Fatal("native dynamic gate accepted wrong pin or canonical path")
	}
}
func TestMigrationExecutableRefusesWrongRolesPinsPathsAndContext(t *testing.T) {
	path, rule := migrationVerifierFixture(t)
	ctx := migrationFixtureContext(t, true)
	file, running, err := migrationVerifierFactory(path, rule)
	if err != nil {
		t.Fatal(err)
	}
	wrongHash := rule[:strings.LastIndex(rule, `H"`)+2] + strings.Repeat("0", 40) + `"`
	if verifyMigrationExecutable(ctx, path, wrongHash) != errMigrationUnavailable {
		t.Fatal("different signature accepted")
	}
	for _, bad := range []string{`identifier "com.viant.mechanize.broker" and cdhash H"` + strings.Repeat("1", 40) + `"`, "anchor apple", rule + " or true"} {
		if verifyMigrationExecutable(ctx, path, bad) != errMigrationUnavailable {
			t.Fatal("broad/wrong role accepted")
		}
		if _, _, err = migrationVerifierFactory(path, bad); err != errMigrationUnavailable {
			t.Fatal("wrong role factory accepted")
		}
	}
	if file(ctx, path+"-other", rule) != errMigrationUnavailable || file(ctx, path, wrongHash) != errMigrationUnavailable {
		t.Fatal("factory changed its artifact binding")
	}
	for _, invalid := range []context.Context{nil, context.Background(), masterFixtureContext(t, true), migrationFixtureContext(t, false)} {
		if verifyMigrationExecutable(invalid, path, rule) != errMigrationUnavailable || running(invalid, &os.Process{Pid: 1}, rule) != errMigrationUnavailable {
			t.Fatal("missing native authority/deadline accepted")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if file(cancelled, path, rule) != errMigrationUnavailable {
		t.Fatal("cancelled static check accepted")
	}
	for _, badPath := range []string{"relative", path + "/../other", path + "\n"} {
		if _, _, err = migrationVerifierFactory(badPath, rule); err != errMigrationUnavailable {
			t.Fatal("uncanonical path accepted")
		}
	}
}
func TestMigrationExecutableRefusesChangedSignatureAndUnsafeCustody(t *testing.T) {
	original, rule := migrationVerifierFixture(t)
	bytes, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	ctx := migrationFixtureContext(t, true)
	for _, mode := range []string{"changed-signature", "writable-file", "setuid-file", "hardlink", "symlink-file", "symlink-parent", "public-parent", "fifo"} {
		t.Run(mode, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "worker")
			if err = os.WriteFile(path, bytes, 0o700); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "changed-signature":
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = file.WriteAt([]byte{0xff, 0xff, 0xff, 0xff}, 512)
				_ = file.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "writable-file":
				if err = os.Chmod(path, 0o722); err != nil {
					t.Fatal(err)
				}
			case "setuid-file":
				if err = os.Chmod(path, os.ModeSetuid|0o700); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err = os.Link(path, filepath.Join(dir, "other-link")); err != nil {
					t.Fatal(err)
				}
			case "symlink-file":
				renamed := path + "-real"
				if err = os.Rename(path, renamed); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(renamed, path); err != nil {
					t.Fatal(err)
				}
			case "symlink-parent":
				alias := dir + "-link"
				if err = os.Symlink(dir, alias); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(alias) })
				path = filepath.Join(alias, "worker")
			case "public-parent":
				if err = os.Chmod(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err = unix.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			result := make(chan error, 1)
			go func() { result <- verifyMigrationExecutable(ctx, path, rule) }()
			select {
			case err := <-result:
				if err != errMigrationUnavailable {
					t.Fatal("unsafe custody accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("nonregular inspection blocked")
			}
		})
	}
}
func TestMigrationRunningVerifierRefusesExitedOtherPathAndDifferentProcessObject(t *testing.T) {
	path, rule := migrationVerifierFixture(t)
	ctx := migrationFixtureContext(t, true)
	_, running, err := migrationVerifierFactory(path, rule)
	if err != nil {
		t.Fatal(err)
	}
	process, stop := startMigrationVerifierFixture(t, path)
	if err = running(ctx, process, rule); err != nil {
		t.Fatal(err)
	}
	borrowed, err := os.FindProcess(process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer borrowed.Release()
	if err = running(ctx, borrowed, rule); err != errMigrationUnavailable {
		t.Fatal("borrowed process object accepted")
	}
	_, running, err = migrationVerifierFactory(path, rule)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if err = running(ctx, process, rule); err != errMigrationUnavailable {
		t.Fatal("exited child accepted")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(path), "same-bytes-other-path")
	if err = os.WriteFile(other, contents, 0o700); err != nil {
		t.Fatal(err)
	}
	otherProcess, _ := startMigrationVerifierFixture(t, other)
	_, running, err = migrationVerifierFactory(path, rule)
	if err != nil {
		t.Fatal(err)
	}
	if err = running(ctx, otherProcess, rule); err != errMigrationUnavailable {
		t.Fatal("different canonical executable accepted")
	}
}
func TestMigrationRunningVerifierRejectsBirthIdentityChangesAroundDynamicCheck(t *testing.T) {
	path, rule := migrationVerifierFixture(t)
	for _, mode := range []string{"birth-during-check", "birth-next-call", "uid", "path", "pid", "dead", "inspection-error", "code-error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(migrationFixtureContext(t, true))
			defer cancel()
			process := &os.Process{Pid: 43210}
			identity := session.ProcessIdentity{PID: process.Pid, UID: uint32(os.Getuid()), Executable: path, StartToken: "100:1"}
			calls, codeCalls := 0, 0
			verifier := &migrationRunningVerifier{path: path, requirement: rule}
			verifier.inspect = func(int) (session.ProcessIdentity, bool, error) {
				calls++
				current := identity
				switch mode {
				case "birth-during-check":
					if calls >= 2 {
						current.StartToken = "100:2"
					}
				case "birth-next-call":
					if calls >= 3 {
						current.StartToken = "100:2"
					}
				case "uid":
					current.UID++
				case "path":
					current.Executable += "-other"
				case "pid":
					current.PID++
				case "dead":
					return current, false, nil
				case "inspection-error":
					return current, false, errors.New("private-native-inspector-canary")
				case "cancel":
					cancel()
				}
				return current, true, nil
			}
			verifier.verifyCode = func(int, string, string) bool { codeCalls++; return mode != "code-error" }
			err := verifier.verify(ctx, process, rule)
			if mode == "birth-next-call" {
				if err != nil {
					t.Fatal("initial exact identity refused")
				}
				err = verifier.verify(ctx, process, rule)
			}
			if err != errMigrationUnavailable || !verifier.failed {
				t.Fatal("changed or unavailable identity accepted")
			}
			previousCodeCalls := codeCalls
			if err = verifier.verify(migrationFixtureContext(t, true), process, rule); err != errMigrationUnavailable || codeCalls != previousCodeCalls {
				t.Fatal("failed verifier adopted replacement")
			}
		})
	}
}
