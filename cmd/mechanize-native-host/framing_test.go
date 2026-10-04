package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
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
	if err = <-done; err != io.EOF {
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
