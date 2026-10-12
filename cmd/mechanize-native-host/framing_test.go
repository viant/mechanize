package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buffer bytes.Buffer
	input := json.RawMessage(`{"requestId":"abc","unicode":"λ"}`)
	if err := WriteFrame(&buffer, input); err != nil {
		t.Fatal(err)
	}
	if binary.NativeEndian.Uint32(buffer.Bytes()[:4]) != uint32(len(input)) {
		t.Fatal("wrong native endian header")
	}
	result, err := ReadFrame(&buffer)
	if err != nil || !bytes.Equal(result, input) {
		t.Fatalf("round trip: %s %v", result, err)
	}
}

func TestFramesRejectMalformedOversizedAndTruncated(t *testing.T) {
	for _, length := range []uint32{0, MaxFrameBytes + 1, 1 << 30} {
		var header [4]byte
		binary.NativeEndian.PutUint32(header[:], length)
		if _, err := ReadFrame(bytes.NewReader(header[:])); err == nil {
			t.Fatal("accepted invalid length")
		}
	}
	var header [4]byte
	binary.NativeEndian.PutUint32(header[:], 10)
	if _, err := ReadFrame(bytes.NewReader(append(header[:], []byte(`{}`)...))); err == nil {
		t.Fatal("accepted truncated frame")
	}
	if err := WriteFrame(io.Discard, json.RawMessage(`not json`)); err == nil {
		t.Fatal("accepted invalid JSON")
	}
	if err := WriteFrame(io.Discard, json.RawMessage{'"', 0xff, '"'}); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
}

func TestBridgeAuthenticatesOnceWithoutReplay(t *testing.T) {
	host, broker := net.Pipe()
	defer broker.Close()
	var input, output bytes.Buffer
	_ = WriteFrame(&input, json.RawMessage(`{"type":"hello","protocolVersion":1,"profileChannel":"profile1","browserInstance":"browser1","credential":"forged","profileDirectory":"/forged/profile","profileLaunchQualified":true}`))
	_ = WriteFrame(&input, json.RawMessage(`{"requestId":"receipt1","dispatchState":"dispatched"}`))
	attention := json.RawMessage(`{"type":"attention","error":{"code":"storedFenceMismatch"},"reconnectPhase":"journal","reconnectReason":"journalChanged","reconnectJournal":{"reason":"historyLimit","version":1,"historyCount":64,"state":"adopted","grantRelation":"new"}}`)
	_ = WriteFrame(&input, attention)
	config := &Config{ProfileChannel: "profile1", BrowserInstance: "browser1", ExtensionOrigin: "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/", FixtureEnrollment: true}
	done := make(chan error, 1)
	go func() { done <- Bridge(&input, &output, host, config, "host-owned-credential") }()
	hello, err := ReadFrame(broker)
	if err != nil {
		t.Fatal(err)
	}
	var enrollment map[string]any
	_ = json.Unmarshal(hello, &enrollment)
	if enrollment["credential"] != "host-owned-credential" || enrollment["extensionOrigin"] != config.ExtensionOrigin || enrollment["profileDirectory"] != config.ProfileDirectory || enrollment["profileLaunchQualified"] != false {
		t.Fatal("untrusted hello fields accepted")
	}
	receipt, err := ReadFrame(broker)
	if err != nil || !bytes.Contains(receipt, []byte("receipt1")) {
		t.Fatalf("receipt not forwarded: %s %v", receipt, err)
	}
	forwarded, err := ReadFrame(broker)
	if err != nil || !bytes.Equal(forwarded, attention) {
		t.Fatal("native bridge changed bounded journal attention")
	}
	if err = <-done; !errors.Is(err, io.EOF) {
		t.Fatalf("bridge completion: %v", err)
	}
}

func TestBridgeRejectsProfileForgery(t *testing.T) {
	host, broker := net.Pipe()
	defer broker.Close()
	defer host.Close()
	var input bytes.Buffer
	_ = WriteFrame(&input, json.RawMessage(`{"type":"hello","protocolVersion":1,"profileChannel":"other","browserInstance":"browser1"}`))
	if err := Bridge(&input, io.Discard, host, &Config{ProfileChannel: "profile1", BrowserInstance: "browser1"}, "credential"); err == nil {
		t.Fatal("accepted forged profile")
	}
}

func TestPrivatePlaywrightLargeFrameKeepsOrdinaryLimit(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 343078)
	raw, _ := json.Marshal(map[string]any{"type": "playwright.send", "requestId": "request", "relayId": "relay", "deadlineUnixMs": 123, "method": "Runtime.evaluate", "params": map[string]string{"expression": string(payload)}})
	var buffer bytes.Buffer
	if len(raw) <= MaxFrameBytes || len(raw) >= 1024*1024 || WriteFrame(&buffer, raw) != nil {
		t.Fatal("real injection sized private frame refused")
	}
	actual, err := ReadFrame(&buffer)
	if err != nil || !bytes.Equal(actual, raw) {
		t.Fatal("private native frame changed")
	}
	ordinary, _ := json.Marshal(map[string]string{"type": "command", "value": string(payload)})
	if WriteFrame(io.Discard, ordinary) == nil {
		t.Fatal("ordinary frame cap widened")
	}
	duplicate := append([]byte(`{"type":"playwright.send",`), raw[1:]...)
	if WriteFrame(io.Discard, duplicate) == nil {
		t.Fatal("duplicate private type allowed")
	}
	oversized, _ := json.Marshal(map[string]any{"type": "playwright.result", "requestId": "r", "relayId": "relay", "result": string(bytes.Repeat([]byte("x"), 512*1024))})
	if WriteFrame(io.Discard, oversized) == nil {
		t.Fatal("private cap exceeded")
	}
}
