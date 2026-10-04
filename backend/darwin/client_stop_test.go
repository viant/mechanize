package darwin

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This child speaks only framed metadata and cleanup acknowledgements. It has no
// macOS input APIs and accepts no application action or input dispatch request.
func TestStopPhaseHelperProcess(t *testing.T) {
	mode := os.Getenv("MECHANIZE_STOP_PHASE_FIXTURE")
	if mode == "" {
		return
	}
	_, _ = os.Stderr.Write([]byte("ready\n"))
	for {
		data, err := readFrame(os.Stdin)
		if err != nil {
			os.Exit(0)
		}
		var request Request
		if json.Unmarshal(data, &request) != nil {
			os.Exit(2)
		}
		if request.Method != "doctor" && request.Method != "input.releaseAll" {
			os.Exit(3)
		}
		if mode == "delayed" {
			time.Sleep(300 * time.Millisecond)
		}
		if mode == "doctorTimeout" && request.Method == "doctor" || mode == "releaseTimeout" && request.Method == "input.releaseAll" {
			time.Sleep(700 * time.Millisecond)
		}
		reply := Reply{ProtocolVersion: 1, RequestID: request.RequestID, HelperEpoch: "stop-fixture", Result: json.RawMessage(`{}`)}
		if request.Method == "input.releaseAll" {
			if request.HelperEpoch != "stop-fixture" {
				os.Exit(4)
			}
			ack := map[string]any{"revoked": true, "unknownReleases": 0, "businessOutcomeUnknown": false}
			switch mode {
			case "missingUnknown":
				delete(ack, "unknownReleases")
			case "nullUnknown":
				ack["unknownReleases"] = nil
			case "wrongUnknown":
				ack["unknownReleases"] = "PRIVATE_SECRET"
			case "negativeUnknown":
				ack["unknownReleases"] = -1
			case "unknownReleases":
				ack["unknownReleases"] = 1
			case "missingBusiness":
				delete(ack, "businessOutcomeUnknown")
			case "nullBusiness":
				ack["businessOutcomeUnknown"] = nil
			case "wrongBusiness":
				ack["businessOutcomeUnknown"] = "PRIVATE_SECRET"
			case "missingRevoked":
				delete(ack, "revoked")
			case "nullRevoked":
				ack["revoked"] = nil
			case "wrongRevoked":
				ack["revoked"] = "PRIVATE_SECRET"
			case "falseRevoked":
				ack["revoked"] = false
			case "extraField":
				ack["privateValue"] = "PRIVATE_TOKEN"
			case "receiptUnknown":
				reply.Receipt = &Receipt{DispatchState: "unknown"}
			case "epochChanged":
				reply.HelperEpoch = "different-helper"
			case "nativeError":
				reply.Error = &NativeError{Code: "privateCode", Message: "PRIVATE_NATIVE_MESSAGE"}
			}
			reply.Result, _ = json.Marshal(ack)
		}
		data, _ = json.Marshal(reply)
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(data)))
		if writeAll(os.Stdout, header[:]) != nil || writeAll(os.Stdout, data) != nil {
			os.Exit(0)
		}
	}
}
func stopPhaseFixture(t *testing.T, mode string) *Client {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
	script := filepath.Join(t.TempDir(), "helper.sh")
	body := "#!/bin/sh\nMECHANIZE_STOP_PHASE_FIXTURE=" + quote(mode) + " exec " + quote(executable) + " -test.run='^TestStopPhaseHelperProcess$'\n"
	if err = os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	ready, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	defer writer.Close()
	client, err := NewClient(context.Background(), Options{HelperPath: script, Stderr: writer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err = ready.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var bytes [6]byte
	if _, err = io.ReadFull(ready, bytes[:]); err != nil || string(bytes[:]) != "ready\n" {
		t.Fatal("inert helper readiness unavailable")
	}
	client.inputPossible = true
	client.businessPossible = true
	return client
}
func TestStopSeparatePhaseBudgetsPermitDelayedDoctorAndRelease(t *testing.T) {
	client := stopPhaseFixture(t, "delayed")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	report, err := client.Stop(ctx)
	if err != nil || report.UnknownInputs || !report.InputInhibited || !report.HelperStopped || !report.BusinessOutcomeUnknown {
		t.Fatalf("independent cleanup budgets failed: %+v %v", report, err)
	}
	if time.Since(start) < 550*time.Millisecond {
		t.Fatal("fixture did not exercise both delayed phases")
	}
}
func TestStopCleanupTimeoutsIdentifyPhaseAndRetainPhysicalUncertainty(t *testing.T) {
	for _, mode := range []string{"doctorTimeout", "releaseTimeout"} {
		t.Run(mode, func(t *testing.T) {
			client := stopPhaseFixture(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			report, err := client.Stop(ctx)
			var failure *StopCleanupError
			phase := "doctor"
			if mode == "releaseTimeout" {
				phase = "release"
			}
			if !errors.As(err, &failure) || failure.Phase != phase || failure.CauseCode != "deadline" || !report.UnknownInputs || !report.HelperStopped || !report.BusinessOutcomeUnknown {
				t.Fatalf("timeout erased phase/uncertainty: %+v %v", report, err)
			}
		})
	}
}
func TestStopAcknowledgementRequiresExplicitTypedFieldsAndSameHelper(t *testing.T) {
	for _, mode := range []string{"missingUnknown", "nullUnknown", "wrongUnknown", "negativeUnknown", "missingBusiness", "nullBusiness", "wrongBusiness", "missingRevoked", "nullRevoked", "wrongRevoked", "falseRevoked", "extraField", "receiptUnknown", "epochChanged", "nativeError", "unknownReleases"} {
		t.Run(mode, func(t *testing.T) {
			client := stopPhaseFixture(t, mode)
			report, err := client.Stop(context.Background())
			var failure *StopCleanupError
			if !errors.As(err, &failure) || failure.Phase != "release" || !report.UnknownInputs || !report.HelperStopped || !report.BusinessOutcomeUnknown {
				t.Fatalf("bad ACK qualified cleanup: %+v %v", report, err)
			}
			if strings.Contains(report.Reason, "PRIVATE") || strings.Contains(err.Error(), "PRIVATE") || strings.Contains(report.Reason, "helper.sh") {
				t.Fatal("cleanup diagnostics leaked private material")
			}
		})
	}
}
func TestStopCallerDeadlineRemainsTotalBoundWhileReapingContinues(t *testing.T) {
	client := stopPhaseFixture(t, "delayed")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	report, err := client.Stop(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || !report.UnknownInputs || report.HelperStopped || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("cleanup ignored total caller bound: elapsed=%s report=%+v err=%v", time.Since(start), report, err)
	}
	// Join only the inert child teardown; this is not a new cleanup request/replay.
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestStopValidAckDoesNotClaimBusinessCompletion(t *testing.T) {
	client := stopPhaseFixture(t, "valid")
	report, err := client.Stop(context.Background())
	if err != nil || report.UnknownInputs || !report.HelperStopped || !report.BusinessOutcomeUnknown {
		t.Fatalf("physical ACK became business proof: %+v %v", report, err)
	}
}
