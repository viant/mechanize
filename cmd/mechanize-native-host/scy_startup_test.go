package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viant/scy"
)

// The child runs the actual native-host startup with encrypted Scy loading.
// FixtureEnrollment bypasses only unavailable browser signature proof; it does
// not substitute or bypass the encrypted credential provider.
func TestNativeHostScyStartupChild(t *testing.T) {
	if os.Getenv("MECHANIZE_TEST_SCY_STARTUP_CHILD") != "1" {
		t.Skip("subprocess-only startup fixture")
	}
	os.Args = []string{os.Args[0], os.Getenv("MECHANIZE_TEST_SCY_STARTUP_ORIGIN")}
	if err := run(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal("native host startup failed")
	}
}
func TestNativeHostStartupDecryptsRealScyEnvKeyEnrollment(t *testing.T) {
	const envKey = "MECHANIZE_TEST_NATIVE_ENROLLMENT_KEY"
	t.Setenv(envKey, "fixture-native-env-key-32-bytes-x")
	dir, dirErr := os.MkdirTemp("", "mscy-")
	if dirErr != nil {
		t.Fatal(dirErr)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	dir, dirErr = filepath.EvalSymlinks(dir)
	if dirErr != nil {
		t.Fatal(dirErr)
	}
	os.Chmod(dir, 0700)
	resource := scy.Resource{URL: filepath.Join(dir, "enrollment.sec"), Key: "blowfish://env/" + envKey}
	credential := strings.Repeat("native-fixture-enrollment-", 3)
	if err := scy.New().Store(context.Background(), scy.NewSecret(credential, &resource)); err != nil {
		t.Fatal("encrypted Scy store failed")
	}
	ciphertext, err := os.ReadFile(resource.URL)
	if err != nil || len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte(credential)) {
		t.Fatal("raw enrollment resource was not encrypted")
	}
	os.Chmod(resource.URL, 0600)
	os.Chmod(dir, 0700)
	socket := filepath.Join(dir, "broker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	os.Chmod(socket, 0600)
	origin := "chrome-extension://" + strings.Repeat("a", 32) + "/"
	config := Config{FixtureEnrollment: true, SocketPath: socket, ExtensionOrigin: origin, ProfileChannel: "encrypted-profile", BrowserInstance: "encrypted-browser", CredentialResource: resource}
	cfgPath := filepath.Join(dir, "host.json")
	encoded, _ := json.Marshal(config)
	if err = os.WriteFile(cfgPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan bool, 1)
	go func() {
		listener.SetDeadline(time.Now().Add(3 * time.Second))
		conn, e := listener.Accept()
		if e != nil {
			received <- false
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		raw, e := ReadFrame(conn)
		var hello map[string]any
		if e != nil || json.Unmarshal(raw, &hello) != nil {
			received <- false
			return
		}
		received <- hello["credential"] == credential
	}()
	var input bytes.Buffer
	WriteFrame(&input, json.RawMessage(`{"type":"hello","protocolVersion":1,"profileChannel":"encrypted-profile","browserInstance":"encrypted-browser"}`))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestNativeHostScyStartupChild$")
	cmd.Env = append(os.Environ(), "MECHANIZE_TEST_SCY_STARTUP_CHILD=1", "MECHANIZE_TEST_SCY_STARTUP_ORIGIN="+origin, "MECHANIZE_NATIVE_HOST_CONFIG="+cfgPath)
	cmd.Stdin = &input
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Run(); err != nil {
		t.Fatal("actual native host startup failed to decrypt encrypted env-key Scy resource")
	}
	if !<-received {
		t.Fatal("broker did not receive exact Scy-decrypted enrollment credential")
	}
}
