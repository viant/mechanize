package darwin

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func captureFrame(nonce [16]byte, body []byte) []byte {
	var out bytes.Buffer
	out.WriteString("MCAP")
	out.Write(nonce[:])
	_ = binary.Write(&out, binary.BigEndian, uint32(len(body)))
	out.Write(body)
	return out.Bytes()
}

func TestCaptureFramesAreBoundedAndCorrelated(t *testing.T) {
	nonce := [16]byte{1, 2, 3}
	valid := captureFrame(nonce, []byte("fixture"))
	wrong := append([]byte(nil), valid...)
	wrong[4]++
	over := append([]byte(nil), valid...)
	binary.BigEndian.PutUint32(over[20:24], MaximumCaptureBytes+1)
	for _, body := range [][]byte{valid[:3], valid[:23], valid[:len(valid)-1], wrong, over} {
		if _, err := readCaptureFrame(bytes.NewReader(body), nonce, 1024); err == nil {
			t.Fatal("malformed/foreign capture frame accepted")
		}
	}
	if _, err := readCaptureFrame(bytes.NewReader(valid), nonce, -1); err == nil {
		t.Fatal("invalid budget accepted")
	}
	got, err := readCaptureFrame(bytes.NewReader(valid), nonce, 1024)
	if err != nil || string(got) != "fixture" {
		t.Fatalf("roundtrip: %s %v", got, err)
	}
}

// The subprocess generates a PNG fixture in memory. It calls no desktop API.
func TestCaptureHelperProcess(t *testing.T) {
	mode := os.Getenv("MECHANIZE_CAPTURE_FIXTURE")
	if mode == "" {
		return
	}
	for {
		data, err := readFrame(os.Stdin)
		if err != nil {
			os.Exit(0)
		}
		var request Request
		_ = json.Unmarshal(data, &request)
		reply := Reply{ProtocolVersion: 1, RequestID: request.RequestID, HelperEpoch: "capture-fixture-epoch", Result: json.RawMessage(`{}`)}
		if request.Method == "capture.image" {
			if mode == "block" {
				time.Sleep(time.Minute)
				os.Exit(0)
			}
			var params struct {
				Nonce    string `json:"captureNonce"`
				Bundle   string `json:"bundleId"`
				PID      int32  `json:"pid"`
				WindowID uint32 `json:"windowID"`
			}
			_ = json.Unmarshal(request.Params, &params)
			decoded, _ := hex.DecodeString(params.Nonce)
			var nonce [16]byte
			copy(nonce[:], decoded)
			var body bytes.Buffer
			_ = png.Encode(&body, image.NewRGBA(image.Rect(0, 0, 16, 12)))
			if mode == "invalid-png" {
				body.Reset()
				body.WriteString("invalid")
			}
			frame := captureFrame(nonce, body.Bytes())
			switch mode {
			case "wrong-nonce":
				frame[4]++
			case "oversized":
				binary.BigEndian.PutUint32(frame[20:24], MaximumCaptureBytes+1)
				frame = frame[:24]
			case "partial":
				frame = frame[:len(frame)-1]
			}
			output := os.NewFile(3, "fixture-capture-pipe")
			_ = writeAll(output, frame)
			if mode == "partial" {
				os.Exit(0)
			}
			metadata := CaptureMetadata{CaptureID: "fixture-image", ProcessStartToken: "1790000000:1", Nonce: params.Nonce, Identity: "window:42", BundleID: params.Bundle, PID: params.PID, WindowID: params.WindowID, Width: 16, Height: 12, Bytes: body.Len(), ReturnedAt: time.Now().UTC().Format(time.RFC3339), Scale: 1, CoordinateSpace: "globalLogicalPoints", Bounds: CaptureBounds{X: -1920, Y: 20, Width: 16, Height: 12}}
			if mode == "missing-process-token" {
				metadata.ProcessStartToken = ""
			}
			if mode == "reused-process" {
				metadata.ProcessStartToken = "1790000000:2"
			}
			if mode == "wrong-scope" {
				metadata.BundleID = "other.app"
			}
			if mode == "wrong-size" {
				metadata.Bytes++
			}
			if mode == "stale" {
				metadata.ReturnedAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
			}
			if mode == "wrong-geometry" {
				metadata.Bounds.Width = 100
			}
			reply.Result, _ = json.Marshal(metadata)
		}
		encoded, _ := json.Marshal(reply)
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(encoded)))
		_ = writeAll(os.Stdout, header[:])
		_ = writeAll(os.Stdout, encoded)
	}
}

func captureHelper(t *testing.T, mode string) string {
	t.Helper()
	binaryPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "capture-helper.sh")
	quote := "'" + strings.ReplaceAll(binaryPath, "'", "'\\''") + "'"
	script := "#!/bin/sh\nMECHANIZE_CAPTURE_FIXTURE=" + mode + " exec " + quote + " -test.run='^TestCaptureHelperProcess$'\n"
	if err = os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWindowCaptureIsolatedTransport(t *testing.T) {
	for _, mode := range []string{"success", "missing-process-token", "reused-process", "wrong-nonce", "oversized", "partial", "wrong-scope", "wrong-size", "invalid-png", "stale", "wrong-geometry", "block"} {
		t.Run(mode, func(t *testing.T) {
			helper := captureHelper(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if mode == "block" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 80*time.Millisecond)
			}
			defer cancel()
			options := WindowCaptureOptions{HelperPath: helper, BundleID: "fixture.app", ProcessStartToken: "1790000000:1", PID: 123, WindowID: 42, MaxBytes: 4096, Stderr: io.Discard}
			result, err := CaptureWindow(ctx, options)
			if mode == "success" {
				if err != nil || len(result.PNG) == 0 || result.Metadata.BundleID != options.BundleID {
					t.Fatalf("capture: %+v %v", result.Metadata, err)
				}
				second, err := CaptureWindow(ctx, options)
				if err != nil || result.Metadata.Nonce == second.Metadata.Nonce {
					t.Fatalf("capture reused correlation: %v", err)
				}
				return
			}
			var failure *CaptureError
			if !errors.As(err, &failure) || !failure.CleanupConfirmed || len(result.PNG) != 0 {
				t.Fatalf("failed capture cleanup/evidence: %+v %v", result.Metadata, err)
			}
		})
	}
}
