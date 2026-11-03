package darwin

import (
	"context"
	"os/exec"
	"testing"

	"github.com/viant/mechanize/session"
)

func TestStoppedObservationHelperRecoversAfterConsoleReceiptLoss(t *testing.T) {
	process := exec.Command("/bin/sleep", "30")
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Process.Kill(); _ = process.Wait() })
	identity, alive, err := session.InspectProcess(process.Process.Pid)
	if err != nil || !alive || identity.StartToken == "" {
		t.Fatal("fixture identity unavailable", err)
	}
	if err := process.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = process.Wait()
	stopped := make(chan struct{})
	close(stopped)
	old := &Client{observationOnly: true, consoleChild: &consoleChild{pid: identity.PID}, verifiedIdentity: &identity, stopped: stopped, waitErr: ErrPrivateProof}
	old.closeOnce.Do(func() {}) // Transport/heartbeat were already closed on owner loss.
	if err := old.Close(); err != nil {
		t.Fatal("verified exited reader remained poisoned", err)
	}
	if old.consoleChild.reaped.Load() || old.WaitStopped(context.Background()) == nil {
		t.Fatal("lost console receipt was rewritten")
	}
	creates := 0
	r, err := NewReadOnlyCaller(old, func(context.Context) (Caller, error) { creates++; return &readonlyFixture{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	r.invalid = true
	if generation, err := r.PrepareRead(context.Background()); err != nil || generation != 2 || creates != 1 {
		t.Fatal("subsequent request did not recover a new reader generation", generation, err, creates)
	}
	_ = r.Close()
	old.observationOnly = false
	if old.Close() == nil {
		t.Fatal("action-capable helper accepted observation-only exit recovery")
	}
}
