package darwin

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaptureWindowDiscoveryValidation(t *testing.T) {
	now := time.Now().UTC()
	fixture := func() CaptureWindowList {
		return CaptureWindowList{BundleID: "fixture.app", ReturnedAt: now.Format(time.RFC3339), Windows: []CaptureWindowTarget{{BundleID: "fixture.app", PID: 42, ProcessStartToken: "1790000000:1", WindowID: 17, Title: "fixture", Bounds: CaptureBounds{X: -100, Y: 20, Width: 100, Height: 80}}}}
	}
	if err := validateCaptureWindows(fixture(), "fixture.app", 1, now, now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CaptureWindowList){
		"foreign-app": func(r *CaptureWindowList) { r.Windows[0].BundleID = "other.app" }, "foreign-root": func(r *CaptureWindowList) { r.BundleID = "other.app" }, "stale": func(r *CaptureWindowList) { r.ReturnedAt = now.Add(-time.Minute).Format(time.RFC3339) }, "future": func(r *CaptureWindowList) { r.ReturnedAt = now.Add(time.Minute).Format(time.RFC3339) }, "missing-token": func(r *CaptureWindowList) { r.Windows[0].ProcessStartToken = "" }, "invalid-token": func(r *CaptureWindowList) { r.Windows[0].ProcessStartToken = "start" }, "bad-pid": func(r *CaptureWindowList) { r.Windows[0].PID = 0 }, "bad-window": func(r *CaptureWindowList) { r.Windows[0].WindowID = 0 }, "oversized": func(r *CaptureWindowList) { r.Windows = append(r.Windows, r.Windows[0]) }, "nan-bounds": func(r *CaptureWindowList) { r.Windows[0].Bounds.X = math.NaN() }, "title": func(r *CaptureWindowList) { r.Windows[0].Title = string(make([]byte, 1025)) }, "false-truncation": func(r *CaptureWindowList) { r.Windows = nil; r.Truncated = true },
	} {
		t.Run(name, func(t *testing.T) {
			r := fixture()
			change(&r)
			if validateCaptureWindows(r, "fixture.app", 1, now, now) == nil {
				t.Fatal("invalid discovery accepted")
			}
		})
	}
	empty := fixture()
	empty.Windows = nil
	if err := validateCaptureWindows(empty, "fixture.app", 1, now, now); err != nil {
		t.Fatal(err)
	}
	bounded := fixture()
	bounded.Truncated = true
	if err := validateCaptureWindows(bounded, "fixture.app", 1, now, now); err != nil {
		t.Fatal(err)
	}
}

// This helper returns only fixture JSON; it never calls a desktop or TCC API.
func TestCaptureWindowsHelperProcess(t *testing.T) {
	if os.Getenv("MECHANIZE_WINDOWS_FIXTURE") == "" {
		return
	}
	for {
		body, err := readFrame(os.Stdin)
		if err != nil {
			os.Exit(0)
		}
		var request Request
		_ = json.Unmarshal(body, &request)
		reply := Reply{ProtocolVersion: 1, RequestID: request.RequestID, HelperEpoch: "windows-fixture", Result: json.RawMessage(`{}`)}
		if request.Method == "capture.windows" {
			var params struct {
				Bundle string `json:"bundleId"`
				Limit  int    `json:"limit"`
			}
			_ = json.Unmarshal(request.Params, &params)
			if params.Bundle != "fixture.app" || params.Limit != 1 || request.HelperEpoch != "windows-fixture" {
				os.Exit(3)
			}
			value := CaptureWindowList{BundleID: params.Bundle, ReturnedAt: time.Now().UTC().Format(time.RFC3339), Truncated: true, Windows: []CaptureWindowTarget{{BundleID: params.Bundle, PID: 42, ProcessStartToken: "1790000000:1", WindowID: 17, Title: "Fixture", Bounds: CaptureBounds{X: -100, Y: 20, Width: 100, Height: 80}}}}
			reply.Result, _ = json.Marshal(value)
		}
		encoded, _ := json.Marshal(reply)
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(encoded)))
		if writeAll(os.Stdout, header[:]) != nil || writeAll(os.Stdout, encoded) != nil {
			os.Exit(4)
		}
	}
}
func TestCaptureWindowsDisposableFixture(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "helper.sh")
	// The executable path is supplied by the Go runtime, and quoted as shell data.
	text := "#!/bin/sh\nMECHANIZE_WINDOWS_FIXTURE=1 exec '" + strings.ReplaceAll(executable, "'", "'\\''") + "' -test.run '^TestCaptureWindowsHelperProcess$'\n"
	if err = os.WriteFile(script, []byte(text), 0700); err != nil {
		t.Fatal(err)
	}
	result, err := ListCaptureWindows(context.Background(), CaptureWindowListOptions{HelperPath: script, BundleID: "fixture.app", Limit: 1})
	if err != nil || len(result.Windows) != 1 || !result.Truncated || result.Windows[0].WindowID != 17 {
		t.Fatalf("%+v %v", result, err)
	}
	_, err = ListCaptureWindows(context.Background(), CaptureWindowListOptions{HelperPath: script, BundleID: "fixture.app", Limit: 0})
	var failure *CaptureError
	if !errors.As(err, &failure) || !failure.CleanupConfirmed || failure.DispatchState != "notDispatched" {
		t.Fatalf("%v", err)
	}
}
