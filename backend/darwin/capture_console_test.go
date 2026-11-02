package darwin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaptureConsoleFailureNeverFallsBackToDirectLaunch(t *testing.T) {
	for _, mode := range []string{"windows", "image"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "direct-launch")
			helper := filepath.Join(dir, "helper.sh")
			quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
			if err := os.WriteFile(helper, []byte("#!/bin/sh\ntouch "+quote(marker)+"\nexit 1\n"), 0700); err != nil {
				t.Fatal(err)
			}
			// No authenticated console/handshake is available. A configured route
			// must fail closed instead of launching this valid executable directly.
			route := &ConsoleLaunchOptions{SocketPath: filepath.Join(dir, "absent.sock"), Requirement: "console-pin"}
			var err error
			if mode == "windows" {
				_, err = ListCaptureWindows(context.Background(), CaptureWindowListOptions{Console: route, HelperPath: helper, BundleID: "fixture.app", Limit: 1})
			} else {
				_, err = CaptureWindow(context.Background(), WindowCaptureOptions{Console: route, HelperPath: helper, BundleID: "fixture.app", PID: 42, WindowID: 17, MaxBytes: 1024})
			}
			var failure *CaptureError
			if !errors.Is(err, ErrPrivateProof) || !errors.As(err, &failure) || !failure.CleanupConfirmed || failure.DispatchState != "notDispatched" {
				t.Fatalf("unexpected failure: %+v %v", failure, err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("capture fell back to direct helper launch")
			}
		})
	}
}
