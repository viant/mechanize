package darwin

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"github.com/viant/mechanize/session"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This qualification test only calls nonprompting doctor. It never posts input,
// queries another app's AX tree or captures the user's screen.
func TestNativeWatchdogEOFAndSilence(t *testing.T) {
	helper := os.Getenv("MECHANIZE_NATIVE_HELPER")
	if helper == "" {
		t.Skip("build helper and set MECHANIZE_NATIVE_HELPER for non-input watchdog fixture")
	}
	for _, mode := range []string{"eof", "silence"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer null.Close()
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer read.Close()
			defer write.Close()
			command := exec.CommandContext(ctx, helper)
			command.ExtraFiles = []*os.File{null, read, null}
			stdin, _ := command.StdinPipe()
			stdout, _ := command.StdoutPipe()
			if err = command.Start(); err != nil {
				t.Fatal(err)
			}
			defer command.Process.Kill()
			_, _ = write.Write([]byte{1})
			data, _ := json.Marshal(Request{ProtocolVersion: 1, RequestID: "safe-doctor", Method: "doctor", DeadlineRemainingMS: 500, Params: json.RawMessage(`{}`)})
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], uint32(len(data)))
			if err = writeAll(stdin, header[:]); err != nil {
				t.Fatal(err)
			}
			if err = writeAll(stdin, data); err != nil {
				t.Fatal(err)
			}
			reply, err := readFrame(stdout)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Reply
			if err = json.Unmarshal(reply, &decoded); err != nil || decoded.HelperEpoch == "" {
				t.Fatalf("doctor failed: %s %v", reply, err)
			}
			started := time.Now()
			if mode == "eof" {
				_ = write.Close()
			}
			err = command.Wait()
			if err == nil {
				t.Fatal("watchdog must terminate helper with inhibited exit status")
			}
			if ctx.Err() != nil {
				t.Fatal("watchdog failed to stop independently of stdin")
			}
			if mode == "eof" && time.Since(started) > time.Second {
				t.Fatal("watchdog EOF stop exceeded bound")
			}
			_, _ = io.Copy(io.Discard, stdout)
		})
	}
}

func TestNativeSupervisorEnrollmentWithoutInput(t *testing.T) {
	helper := os.Getenv("MECHANIZE_NATIVE_HELPER")
	if helper == "" {
		t.Skip("build helper for non-input enrollment fixture")
	}
	ctx, p := nativeActor(t)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	supervisor, err := session.NewSupervisor(session.Options{LockPath: filepath.Join(directory, "desktop.lock"), HelperExecutable: helper})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = supervisor.Acquire(ctx, p, session.Scope{AllowedBundles: []string{"fixture.app"}}); err != nil {
		t.Fatal(err)
	}
	fence, err := supervisor.FenceFile(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, Options{HelperPath: helper, Fence: fence})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	identity, err := client.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err = supervisor.AttachHelper(ctx, p, identity, client.Stop); err != nil {
		t.Fatal(err)
	}
	reply, err := client.Call(ctx, Request{ProtocolVersion: 1, RequestID: "enrolled-doctor", Method: "doctor", DeadlineRemainingMS: 1000, Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	var doctor struct {
		Enrolled bool `json:"physicalFenceEnrolled"`
		Mutation bool `json:"mutationEnabled"`
	}
	if err = json.Unmarshal(reply.Result, &doctor); err != nil || !doctor.Enrolled || doctor.Mutation {
		t.Fatalf("unsafe enrollment doctor: %s %v", reply.Result, err)
	}
	report, err := supervisor.Close(ctx)
	if err != nil || !report.HelperStopped || !report.FenceReleased || report.UnknownInputs {
		t.Fatalf("non-input cleanup: %+v %v", report, err)
	}
}
