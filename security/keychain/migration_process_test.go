//go:build darwin || linux

package keychain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Runs only a private protocol fixture in an owned child. No native migration,
// Keychain operation or application automation occurs.
func TestMigrationProcessFixture(t *testing.T) {
	mode := ""
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			mode = os.Args[i+1]
		}
	}
	if mode == "" {
		return
	}
	if os.Getenv("MECHANIZE_TEST_PRIVATE_CANARY") != "" {
		os.Exit(20)
	}
	fmt.Fprint(os.Stderr, "private-fixture-stderr-canary")
	if mode == "console" {
		file := os.NewFile(3, "private-native-console")
		if !migrationConsoleDescriptor(file) {
			os.Exit(23)
		}
		ready := os.NewFile(4, "private-readiness")
		if _, err := ready.Write([]byte("MMREADY1")); err != nil {
			os.Exit(25)
		}
		ready.Close()
		var frame [5]byte
		if _, err := io.ReadFull(file, frame[:]); err != nil || string(frame[:]) != "local" {
			os.Exit(24)
		}
		file.Close()
	}
	for {
		request, err := readMigrationWorkerRequest(os.Stdin)
		if err != nil {
			os.Exit(0)
		}
		if mode == "hang" && request.Operation == "commit" {
			time.Sleep(time.Minute)
			os.Exit(21)
		}
		response := migrationWorkerResponse{Version: 1, ID: request.ID, Session: request.Session, Status: "verified"}
		switch request.Operation {
		case "prepare":
			response.Status = "prepared"
			response.Identity = []byte("public-fixture-reference")
		case "verify":
			response.Status = "checked"
		case "close":
			response.Status = "closed"
		}
		if mode == "wrong" {
			response.Session = strings.Repeat("0", 64)
		}
		if writeMigrationWorkerResponse(os.Stdout, response) != nil {
			os.Exit(22)
		}
		if request.Operation == "close" {
			os.Exit(0)
		}
	}
}
func migrationProcessFixture(t *testing.T, mode string) (*migrationChildProcess, context.Context) {
	return migrationProcessFixtureWithConsole(t, mode, nil)
}
func migrationProcessFixtureWithConsole(t *testing.T, mode string, console *os.File) (*migrationChildProcess, context.Context) {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx := migrationFixtureContext(t, true)
	spec := migrationProcessSpec{executable: path, requirement: `identifier "com.viant.mechanize.custody-migration" and cdhash H"` + strings.Repeat("1", 40) + `"`, session: strings.Repeat("a", 64), arguments: []string{"-test.run=^TestMigrationProcessFixture$", "--", mode}, verifyFile: func(context.Context, string, string) error { return nil }, verifyRunning: func(context.Context, *os.Process, string) error { return nil }}
	spec.console = console
	child, err := startMigrationChild(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(child.close)
	return child, ctx
}

func TestMigrationProcessInheritsOnlyDedicatedConsoleDescriptor(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	console := os.NewFile(uintptr(fds[0]), "private-native-console")
	peer := os.NewFile(uintptr(fds[1]), "private-native-peer")
	defer console.Close()
	defer peer.Close()
	if _, err := peer.Write([]byte("local")); err != nil {
		t.Fatal(err)
	}
	child, ctx := migrationProcessFixtureWithConsole(t, "console", console)
	// The launcher does not own or close the caller's socket; the child gets
	// only its inherited copy. Protocol output remains ordinary typed receipts.
	if _, err := child.exchange(ctx, migrationProcessRequest(1, "prepare")); err != nil {
		t.Fatal(err)
	}
	if _, err := console.Stat(); err != nil {
		t.Fatal("launcher consumed caller's console descriptor")
	}
}

func TestMigrationConsoleDescriptorRejectsFilesAndDatagrams(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "not-a-socket")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if migrationConsoleDescriptor(nil) || migrationConsoleDescriptor(file) {
		t.Fatal("ordinary file admitted as private console")
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	datagram := os.NewFile(uintptr(fds[0]), "datagram")
	defer datagram.Close()
	if migrationConsoleDescriptor(datagram) {
		t.Fatal("datagram admitted as stream console")
	}
}

func TestMigrationReadinessIsExactClosedFrame(t *testing.T) {
	for _, payload := range []string{"MMREADY1", "MMREADY2", "MMREADY1x", "MMREADY", ""} {
		t.Run(fmt.Sprintf("length-%d-%s", len(payload), payload), func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if _, err = writer.Write([]byte(payload)); err != nil {
				t.Fatal(err)
			}
			writer.Close()
			child := &migrationChildProcess{ready: reader}
			err = child.waitReady(context.Background())
			if (err == nil) != (payload == "MMREADY1") {
				t.Fatal("readiness frame admitted or rejected incorrectly")
			}
		})
	}
}

func TestMigrationReadinessCancellationIsBounded(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	child := &migrationChildProcess{ready: reader}
	if !errors.Is(child.waitReady(ctx), errMigrationUnavailable) {
		t.Fatal("cancelled readiness wait admitted")
	}
}
func migrationProcessRequest(n int, op string) migrationWorkerRequest {
	return migrationWorkerRequest{Version: 1, ID: fmt.Sprintf("%064x", n), Session: strings.Repeat("a", 64), Operation: op}
}
func TestMigrationProcessPrivateFramesAndEnvironment(t *testing.T) {
	t.Setenv("MECHANIZE_TEST_PRIVATE_CANARY", "synthetic-secret-canary")
	child, ctx := migrationProcessFixture(t, "echo")
	for i, op := range []string{"prepare", "verify", "commit", "inspect", "close"} {
		if _, err := child.exchange(ctx, migrationProcessRequest(i+1, op)); err != nil {
			t.Fatalf("private exchange: %v", err)
		}
	}
	if !child.unknown {
		t.Fatal("transport cleared dispatched uncertainty without coordinator proof")
	}
}
func TestMigrationProcessRejectsCrossSessionAndDuplicateIDs(t *testing.T) {
	child, ctx := migrationProcessFixture(t, "echo")
	request := migrationProcessRequest(1, "prepare")
	if _, err := child.exchange(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err := child.exchange(ctx, request); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("replay admitted")
	}
	request = migrationProcessRequest(2, "verify")
	request.Session = strings.Repeat("b", 64)
	if _, err := child.exchange(ctx, request); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("cross-session admitted")
	}
}
func TestMigrationProcessTimeoutStopsOnlyOwnedChildAndKeepsUnknown(t *testing.T) {
	child, ctx := migrationProcessFixture(t, "hang")
	if _, err := child.exchange(ctx, migrationProcessRequest(1, "prepare")); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := child.exchange(bounded, migrationProcessRequest(2, "commit")); !errors.Is(err, errMigrationUnknown) {
		t.Fatal("stalled commit lost uncertainty")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("owned-child timeout was not bounded")
	}
	select {
	case <-child.done:
	case <-time.After(2 * time.Second):
		t.Fatal("owned child remains live")
	}
	if _, err := child.exchange(ctx, migrationProcessRequest(3, "commit")); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("failed child reused")
	}
}
func TestMigrationProcessMismatchedResponseAndPrivateErrors(t *testing.T) {
	child, ctx := migrationProcessFixture(t, "wrong")
	_, err := child.exchange(ctx, migrationProcessRequest(1, "prepare"))
	if !errors.Is(err, errMigrationUnavailable) || strings.Contains(fmt.Sprint(err), "canary") {
		t.Fatal("wrong response or private stderr escaped")
	}
}
func TestMigrationProcessRequiresQualifiedVerifiersBeforeSpawn(t *testing.T) {
	ctx := migrationFixtureContext(t, true)
	if _, err := startMigrationChild(ctx, migrationProcessSpec{}); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("unqualified child admitted")
	}
	if _, err := startMigrationChild(context.Background(), migrationProcessSpec{}); !errors.Is(err, errMigrationUnavailable) {
		t.Fatal("untrusted child admitted")
	}
}
