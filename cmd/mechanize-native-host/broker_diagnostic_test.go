package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type blockedChromeWriter struct {
	entered chan struct{}
	release chan struct{}
}

func (w *blockedChromeWriter) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return 0, io.ErrClosedPipe
}

func TestBridgeBlockedChromeOutputCannotPreventTeardown(t *testing.T) {
	input, sender := io.Pipe()
	defer input.Close()
	defer sender.Close()
	host, peer := net.Pipe()
	defer host.Close()
	defer peer.Close()
	writer := &blockedChromeWriter{make(chan struct{}), make(chan struct{})}
	defer close(writer.release)
	done := make(chan error, 1)
	go func() {
		done <- Bridge(input, writer, host, &Config{FixtureEnrollment: true, ProfileChannel: "p", BrowserInstance: "b"}, "credential")
	}()
	go WriteFrame(sender, json.RawMessage(`{"type":"hello","protocolVersion":1,"profileChannel":"p","browserInstance":"b"}`))
	if _, err := ReadFrame(peer); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(peer, json.RawMessage(`{"type":"enrolled"}`)); err != nil {
		t.Fatal(err)
	}
	<-writer.entered
	sender.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked output held host teardown")
	}
}

func TestBridgeBrokerStartupDiagnosticIsClosedAndPreForwardOnly(t *testing.T) {
	for _, tc := range []struct {
		name, reply, want string
		acknowledged      bool
	}{
		{"peer", `{"type":"nativeHostError","code":"brokerPeerUnavailable"}`, "brokerPeerUnavailable", false},
		{"enrollment", `{"type":"nativeHostError","code":"brokerEnrollmentRefused"}`, "brokerEnrollmentRefused", false},
		{"extra", `{"type":"nativeHostError","code":"brokerPeerUnavailable","secret":"PRIVATE-CANARY"}`, "brokerHandshakeUnavailable", false},
		{"duplicate", `{"type":"nativeHostError","code":"brokerPeerUnavailable","code":"brokerChannelBusy"}`, "brokerHandshakeUnavailable", false},
		{"unknown", `{"type":"nativeHostError","code":"PRIVATE-CANARY"}`, "brokerHandshakeUnavailable", false},
		{"eof", "", "brokerHandshakeUnavailable", false},
		{"ackEOF", "", "", true},
		{"late", `{"type":"nativeHostError","code":"brokerPeerUnavailable"}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, sender := io.Pipe()
			t.Cleanup(func() { input.Close(); sender.Close() })
			host, broker := net.Pipe()
			t.Cleanup(func() { host.Close(); broker.Close() })
			var output bytes.Buffer
			done := make(chan error, 1)
			go func() {
				done <- Bridge(input, &output, host, &Config{FixtureEnrollment: true, ProfileChannel: "p", BrowserInstance: "b"}, "PRIVATE-CANARY")
			}()
			go WriteFrame(sender, json.RawMessage(`{"type":"hello","protocolVersion":1,"profileChannel":"p","browserInstance":"b"}`))
			if _, err := ReadFrame(broker); err != nil {
				t.Fatal(err)
			}
			if tc.acknowledged {
				if err := WriteFrame(broker, json.RawMessage(`{"type":"enrolled"}`)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.reply != "" {
				_ = WriteFrame(broker, json.RawMessage(tc.reply))
			}
			broker.Close()
			select {
			case bridgeErr := <-done:
				var lateOutput, diagnostics bytes.Buffer
				reportNativeFailure(bridgeErr, &lateOutput, &diagnostics)
				if lateOutput.Len() != 0 || (tc.want != "" && diagnostics.String() != "Mechanize native transport: "+tc.want+"\n") {
					t.Fatal("duplicate stdout or nonclosed stderr", diagnostics.String())
				}
			case <-time.After(time.Second):
				t.Fatal("bridge did not stop")
			}
			if tc.acknowledged {
				_, _ = ReadFrame(&output)
			}
			if tc.want == "" {
				if output.Len() != 0 {
					t.Fatal("late startup output")
				}
				return
			}
			raw, err := ReadFrame(&output)
			want := `{"type":"nativeHostError","code":"` + tc.want + `"}`
			if err != nil || string(raw) != want || output.Len() != 0 || strings.Contains(string(raw), "CANARY") {
				t.Fatalf("closed diagnostic missing: %s %v", raw, err)
			}
		})
	}
}
