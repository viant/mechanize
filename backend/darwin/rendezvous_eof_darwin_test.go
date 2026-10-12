//go:build darwin

package darwin

import (
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/auth/nativepeer"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDarwinRendezvousPeerTokenExpiresAtEOF(t *testing.T) {
	dir, e := os.MkdirTemp("/tmp", "mce-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	server, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	before, e := nativepeer.AuditPID(conn)
	if e != nil {
		t.Fatal(e)
	}
	if n, e := server.Write([]byte{1}); e != nil || n != 1 {
		t.Fatal("fixture acknowledgement write failed")
	}
	server.Close()
	var b [1]byte
	if n, e := conn.Read(b[:]); e != nil || n != 1 || b[0] != 1 {
		t.Fatal("fixture acknowledgement read failed")
	}
	if before != os.Getpid() {
		t.Fatal("unexpected fixture peer")
	}
	if _, e := nativepeer.AuditPID(conn); e == nil {
		t.Fatal("fixture no longer demonstrates Darwin peer-token expiry; review handshake lifetime contract")
	}
}

func TestConsoleTerminalPeerRemainsAuthenticatedUntilAcknowledged(t *testing.T) {
	dir, e := os.MkdirTemp("/tmp", "mct-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	server, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	nonce := strings.Repeat("a", 64)
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		server.SetDeadline(time.Now().Add(time.Second))
		frame, _ := json.Marshal(map[string]any{"version": 1, "nonce": nonce, "state": "exited", "pid": 456, "status": 0})
		if e := consoleWriteFrame(server, frame); e != nil {
			done <- e
			return
		}
		raw, e := readFrameBounded(server, 8192)
		if e != nil {
			done <- e
			return
		}
		var ack map[string]any
		if json.Unmarshal(raw, &ack) != nil || ack["op"] != "reaped" || ack["nonce"] != nonce || ack["pid"] != float64(456) {
			done <- fmt.Errorf("wrong terminal acknowledgement")
			return
		}
		done <- nil
	}()
	child := &consoleChild{conn: conn, pid: 456, nonce: nonce, verify: func() error {
		pid, e := nativepeer.AuditPID(conn)
		if e != nil || pid != os.Getpid() {
			return ErrPrivateProof
		}
		return nil
	}}
	if e := child.wait(); e != nil || !child.reaped.Load() {
		t.Fatalf("live peer terminal proof failed: %v", e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
