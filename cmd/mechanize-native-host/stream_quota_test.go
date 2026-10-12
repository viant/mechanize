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

// Exercise the actual forwarding loop with bounded frames, not an alternate
// image store or parser. Authentication is fixture-only; framing is production.
func TestBridgeBoundedResultsSurviveFormerLifetimeQuota(t *testing.T) {
	host, broker := net.Pipe()
	defer host.Close()
	defer broker.Close()
	input, inputWriter := io.Pipe()
	defer input.Close()
	defer inputWriter.Close()
	output, outputWriter := io.Pipe()
	defer output.Close()
	defer outputWriter.Close()
	done := make(chan error, 1)
	go func() {
		done <- Bridge(input, outputWriter, host, &Config{ProfileChannel: "profile1", BrowserInstance: "browser1", ExtensionOrigin: "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/", FixtureEnrollment: true}, "fixture-credential")
	}()
	go func() {
		_ = WriteFrame(inputWriter, json.RawMessage(`{"type":"hello","protocolVersion":1,"profileChannel":"profile1","browserInstance":"browser1"}`))
	}()
	if _, e := ReadFrame(broker); e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(map[string]any{"type": "controllerResultChunk", "requestId": "approved-original", "data": strings.Repeat("A", 128*1024)})
	count := (64*1024*1024)/len(body) + 2
	wrote := make(chan error, 1)
	go func() {
		for i := 0; i < count; i++ {
			if e := WriteFrame(broker, body); e != nil {
				wrote <- e
				return
			}
		}
		wrote <- WriteFrame(broker, json.RawMessage(`{"type":"controllerResult","requestId":"last","result":{"content":[]}}`))
	}()
	read := make(chan error, 1)
	go func() {
		for i := 0; i < count; i++ {
			frame, e := ReadFrame(output)
			if e != nil {
				read <- e
				return
			}
			if !bytes.Equal(frame, body) {
				read <- io.ErrUnexpectedEOF
				return
			}
		}
		frame, e := ReadFrame(output)
		if e == nil && !bytes.Contains(frame, []byte(`"requestId":"last"`)) {
			e = io.ErrUnexpectedEOF
		}
		read <- e
	}()
	select {
	case e := <-read:
		if e != nil {
			t.Fatal("healthy bounded connection truncated", e)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("bounded forwarding stalled")
	}
	if e := <-wrote; e != nil {
		t.Fatal(e)
	}
	// Credential injection is still rejected after sustained traffic and never
	// reaches Chrome. Closing input also drains the reverse forwarding goroutine.
	if e := WriteFrame(broker, json.RawMessage(`{"type":"controllerResult","credential":"must-not-forward"}`)); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("post-enrollment credential forgery accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("forgery did not terminate bridge")
	}
}
