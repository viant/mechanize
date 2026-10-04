package darwin

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFramesRejectTruncationAndOversize(t *testing.T) {
	for _, data := range [][]byte{{0, 0}, {0, 0, 0, 3, 1}, {0, 32, 0, 1}} {
		if _, err := readFrame(bytes.NewReader(data)); err == nil {
			t.Fatal("invalid frame accepted")
		}
	}
	body := []byte(`{"requestId":"safe"}`)
	var buffer bytes.Buffer
	_ = binary.Write(&buffer, binary.BigEndian, uint32(len(body)))
	buffer.Write(body)
	actual, err := readFrame(&buffer)
	if err != nil || !bytes.Equal(actual, body) {
		t.Fatalf("round trip: %s %v", actual, err)
	}
}
func TestHelperProcess(t *testing.T) {
	if os.Getenv("MECHANIZE_TRANSPORT_FIXTURE") != "1" {
		return
	}
	_, _ = os.Stderr.Write([]byte("ready\n"))
	for {
		data, err := readFrame(os.Stdin)
		if err != nil {
			os.Exit(0)
		}
		var request Request
		_ = json.Unmarshal(data, &request)
		if request.Method == "block" {
			time.Sleep(time.Minute)
			continue
		}
		reply := Reply{ProtocolVersion: 1, RequestID: request.RequestID, HelperEpoch: "fixture-epoch", Result: json.RawMessage(`{"fixture":true}`)}
		if request.Method == "windows.captureFrame" || request.Method == "large-ordinary-reply" {
			reply.Result, _ = json.Marshal(map[string]string{"payload": strings.Repeat("x", MaximumFrameBytes)})
			if bytes.Contains(request.Params, []byte(`"wrongRequest":true`)) {
				reply.RequestID = "foreign-request"
			}
			if bytes.Contains(request.Params, []byte(`"errorReply":true`)) {
				reply.Result = nil
				reply.Error = &NativeError{Code: "fixtureFailure", Stage: "native", Message: strings.Repeat("x", MaximumFrameBytes)}
			}
		}
		if request.Method == "input.releaseAll" {
			reply.Result = json.RawMessage(`{"revoked":true,"unknownReleases":0,"businessOutcomeUnknown":true}`)
		}
		data, _ = json.Marshal(reply)
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(data)))
		_ = writeAll(os.Stdout, header[:])
		_ = writeAll(os.Stdout, data)
	}
}
func fixtureClient(t *testing.T) *Client {
	t.Helper()
	// Dedicated wrapper starts only this test; no desktop APIs or live inputs.
	script, err := os.CreateTemp(t.TempDir(), "helper-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(script, "#!/bin/sh\nMECHANIZE_TRANSPORT_FIXTURE=1 exec '"+executable+"' -test.run='^TestHelperProcess$'\n")
	if err != nil {
		t.Fatal(err)
	}
	_ = script.Close()
	_ = os.Chmod(script.Name(), 0700)
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	client, err := NewClient(context.Background(), Options{HelperPath: script.Name(), Stderr: readyWrite})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	// Shell and Go test-runtime startup are outside the protocol deadline.
	// Wait for the inert fixture to enter its request loop before testing calls.
	if err = readyRead.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ready [6]byte
	if _, err = io.ReadFull(readyRead, ready[:]); err != nil || string(ready[:]) != "ready\n" {
		t.Fatalf("fixture startup readiness: %q %v", ready, err)
	}
	return client
}
func TestClientProtocolAndCancellation(t *testing.T) {
	client := fixtureClient(t)
	reply, err := client.Call(context.Background(), Request{RequestID: "read-1", Method: "doctor", DeadlineRemainingMS: 1000})
	if err != nil || reply.HelperEpoch != "fixture-epoch" {
		t.Fatalf("reply: %+v %v", reply, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = client.Call(ctx, Request{RequestID: "mutation-1", Method: "block", DeadlineRemainingMS: 1000})
	var transport *TransportError
	if !errors.As(err, &transport) || transport.DispatchState != "unknown" {
		t.Fatalf("must preserve unknown dispatch: %v", err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStopSeparatesPhysicalAndBusinessCleanupEvidence(t *testing.T) {
	client := fixtureClient(t)
	client.inputPossible = true
	client.businessPossible = true
	report, err := client.Stop(context.Background())
	if err != nil || report.UnknownInputs || !report.BusinessOutcomeUnknown || !report.HelperStopped {
		t.Fatalf("physical acknowledgement conflated business outcome: %+v %v", report, err)
	}
}

func TestStopAfterTransportDeathUsesImmutableRawAuthority(t *testing.T) {
	for _, raw := range []bool{false, true} {
		client := fixtureClient(t)
		client.inputPossible = raw
		client.businessPossible = true
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		report, err := client.Stop(context.Background())
		if (raw && err == nil) || (!raw && err != nil) || report.UnknownInputs != raw || !report.BusinessOutcomeUnknown || !report.HelperStopped {
			t.Fatalf("missing acknowledgement invented authority or success: raw=%t %+v %v", raw, report, err)
		}
	}
}
