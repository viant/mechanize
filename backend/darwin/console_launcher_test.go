package darwin

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConsoleLauncherTransfersOwnedDescriptorsAndConfirmsReaping(t *testing.T) {
	for _, mode := range []string{"complete", "wrongNonce", "missingExit", "substitutedPeer", "nonzero", "stopTimeout"} {
		t.Run(mode, func(t *testing.T) {
			dir, e := os.MkdirTemp("/tmp", "mch-")
			if e != nil {
				t.Fatal(e)
			}
			defer os.RemoveAll(dir)
			dir, e = filepath.EvalSymlinks(dir)
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(dir, "launcher")
			listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			os.Chmod(path, 0600)
			inputRead, inputWrite, _ := os.Pipe()
			defer inputRead.Close()
			defer inputWrite.Close()
			outputRead, outputWrite, _ := os.Pipe()
			defer outputRead.Close()
			defer outputWrite.Close()
			artifact, _ := os.Open(os.DevNull)
			defer artifact.Close()
			watchRead, watchWrite, _ := os.Pipe()
			defer watchRead.Close()
			defer watchWrite.Close()
			fence, _ := os.Open(os.DevNull)
			defer fence.Close()
			serverResult := make(chan error, 1)
			go func() {
				conn, e := listener.AcceptUnix()
				if e != nil {
					serverResult <- e
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				data := make([]byte, 1)
				oob := make([]byte, unix.CmsgSpace(5*4))
				n, on, flags, _, e := conn.ReadMsgUnix(data, oob)
				if e != nil || n != 1 || data[0] != 1 || flags&unix.MSG_CTRUNC != 0 {
					serverResult <- fmt.Errorf("descriptor marker invalid")
					return
				}
				controls, e := unix.ParseSocketControlMessage(oob[:on])
				if e != nil || len(controls) != 1 {
					serverResult <- fmt.Errorf("ancillary message invalid")
					return
				}
				fds, e := unix.ParseUnixRights(&controls[0])
				if e != nil || len(fds) != 5 {
					serverResult <- fmt.Errorf("descriptor count invalid")
					return
				}
				files := make([]*os.File, len(fds))
				for i, fd := range fds {
					files[i] = os.NewFile(uintptr(fd), "fixture")
					defer files[i].Close()
				}
				raw, e := readFrameBounded(conn, 32768)
				if e != nil {
					serverResult <- e
					return
				}
				var request map[string]any
				if json.Unmarshal(raw, &request) != nil || request["op"] != "launch" || len(request) != 8 {
					serverResult <- fmt.Errorf("launch schema invalid")
					return
				}
				nonce := request["nonce"].(string)
				if mode == "wrongNonce" {
					nonce = strings.Repeat("b", 64)
				}
				reply, _ := json.Marshal(map[string]any{"version": 1, "nonce": nonce, "state": "launched", "pid": 456})
				if e = consoleWriteFrame(conn, reply); e != nil {
					serverResult <- e
					return
				}
				if mode == "wrongNonce" || mode == "substitutedPeer" {
					serverResult <- nil
					return
				}
				b := make([]byte, 4)
				if _, e = io.ReadFull(files[0], b); e != nil || string(b) != "ping" {
					serverResult <- fmt.Errorf("stdin descriptor wrong")
					return
				}
				if _, e = files[1].Write([]byte("pong")); e != nil {
					serverResult <- e
					return
				}
				raw, e = readFrameBounded(conn, 8192)
				if e != nil {
					serverResult <- e
					return
				}
				var stop map[string]any
				json.Unmarshal(raw, &stop)
				if stop["op"] != "stop" || stop["nonce"] != nonce || stop["pid"] != float64(456) {
					serverResult <- fmt.Errorf("stop identity wrong")
					return
				}
				if mode == "stopTimeout" {
					time.Sleep(1200 * time.Millisecond)
				}
				if mode != "missingExit" && mode != "stopTimeout" {
					status := 0
					if mode == "nonzero" {
						status = 9
					}
					reply, _ = json.Marshal(map[string]any{"version": 1, "nonce": nonce, "state": "exited", "pid": 456, "status": status})
					e = consoleWriteFrame(conn, reply)
					if e == nil {
						acknowledged, readErr := readFrameBounded(conn, 8192)
						var ack map[string]any
						if readErr != nil || json.Unmarshal(acknowledged, &ack) != nil || len(ack) != 4 || ack["op"] != "reaped" || ack["nonce"] != nonce || ack["pid"] != float64(456) {
							e = fmt.Errorf("terminal acknowledgement missing")
						}
					}
				}
				serverResult <- e
			}()
			uid := uint32(os.Getuid())
			checks := 0
			verify := func(*net.UnixConn) error {
				checks++
				if mode == "substitutedPeer" && checks >= 4 {
					return ErrPrivateProof
				}
				return nil
			}
			inspect := func(pid int) (session.ProcessIdentity, bool, error) {
				return session.ProcessIdentity{PID: pid, UID: uid, StartToken: "1:1", Executable: "/fixture/console"}, true, nil
			}
			child, e := launchConsoleHelperWith(context.Background(), Options{HelperPath: "/fixture/helper", Requirement: "helper-pin", ExpectedUID: &uid, Console: &ConsoleLaunchOptions{SocketPath: path, Requirement: "console-pin"}}, &identityHandshake{nonce: strings.Repeat("a", 64), directory: dir}, []string{"--private-administration"}, []*os.File{inputRead, outputWrite, artifact, watchRead, fence}, func(nativepeer.Options) (func(*net.UnixConn) error, error) { return verify, nil }, func(*net.UnixConn) (int, error) { return 123, nil }, inspect)
			if mode == "wrongNonce" || mode == "substitutedPeer" {
				if e == nil {
					t.Fatal("unqualified console accepted")
				}
				if e := <-serverResult; e != nil {
					t.Fatal(e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			inputWrite.Write([]byte("ping"))
			b := make([]byte, 4)
			outputRead.SetReadDeadline(time.Now().Add(time.Second))
			if _, e := io.ReadFull(outputRead, b); e != nil || string(b) != "pong" {
				t.Fatal("returned stdout did not match")
			}
			child.stop()
			started := time.Now()
			e = child.wait()
			if mode == "stopTimeout" && time.Since(started) > 1100*time.Millisecond {
				t.Fatal("unconfirmed stop left wait hanging")
			}
			if mode == "nonzero" && (e != ErrConsoleHelperExit || !child.reaped.Load()) {
				t.Fatal("nonzero exit lost failure or reaping evidence")
			}
			if (e == nil) != (mode == "complete") {
				t.Fatalf("wrong terminal classification: %v", e)
			}
			if e := <-serverResult; e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestConsoleOwnerLossRevokesInputAndHeartbeatWithoutClaimingReaping(t *testing.T) {
	dir, e := os.MkdirTemp("/tmp", "mcl-")
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
	inputRead, inputWrite, _ := os.Pipe()
	defer inputRead.Close()
	watchRead, watchWrite, _ := os.Pipe()
	defer watchRead.Close()
	client := &Client{consoleChild: &consoleChild{conn: conn, nonce: strings.Repeat("a", 64), pid: 456, verify: func() error { return ErrPrivateProof }}, input: inputWrite, output: io.NopCloser(strings.NewReader("")), watchdog: watchWrite, stopped: make(chan struct{}), closeSignal: make(chan struct{})}
	go client.waitForExit()
	server.Close()
	for _, file := range []*os.File{inputRead, watchRead} {
		file.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, e := file.Read(b[:]); e != io.EOF {
			t.Fatalf("owner loss did not revoke descriptor: %v", e)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if client.WaitStopped(ctx) == nil || client.Close() == nil || client.consoleChild.reaped.Load() {
		t.Fatal("lost owner falsely confirmed helper cleanup")
	}
}
