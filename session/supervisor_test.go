package session

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func supervisorActor(t *testing.T, subject string) (context.Context, auth.Principal) {
	t.Helper()
	p, err := auth.NewPrincipal("fixture", "", subject, []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	return auth.WithPrincipal(context.Background(), p), p
}

func TestUnattachedLaunchUncertaintySurvivesRestart(t *testing.T) {
	options, _, _ := fixtureOptions(t)
	s, _ := NewSupervisor(options)
	ctx, p := supervisorActor(t, "alice")
	scope := Scope{AllowedBundles: []string{"fixture.app"}}
	if _, err := s.Acquire(ctx, p, scope); err != nil {
		t.Fatal(err)
	}
	otherCtx, other := supervisorActor(t, "bob")
	if err := s.RetainUnknown(otherCtx, other, CleanupReport{}); !errors.Is(err, ErrNoLease) {
		t.Fatalf("foreign owner changed launch barrier: %v", err)
	}
	if err := s.RetainUnknown(ctx, p, CleanupReport{Reason: "launch identity unavailable"}); err != nil {
		t.Fatal(err)
	}
	report, err := s.Close(ctx)
	if !errors.Is(err, ErrCleanupUnknown) || !report.UnknownInputs || report.FenceReleased || report.HelperStopped {
		t.Fatalf("unattached uncertainty released: %+v %v", report, err)
	}
	// Simulate broker process death: its descriptor disappears, while the disk
	// barrier remains. No invented helper identity is needed to reject transfer.
	if err := s.file.Close(); err != nil {
		t.Fatal(err)
	}
	s.file = nil
	next, _ := NewSupervisor(options)
	if _, err := next.Acquire(ctx, p, scope); !errors.Is(err, ErrCleanupUnknown) {
		t.Fatalf("restart forgot uncertain launch: %v", err)
	}
}
func fixtureOptions(t *testing.T) (Options, *bool, ProcessIdentity) {
	t.Helper()
	alive := true
	identity := ProcessIdentity{PID: 123, StartToken: "fixture-start", Executable: "/fixture/helper", UID: uint32(os.Getuid())}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return Options{LockPath: filepath.Join(directory, "desktop.lock"), HelperExecutable: identity.Executable, Inspect: func(pid int) (ProcessIdentity, bool, error) { return identity, alive, nil }}, &alive, identity
}
func TestSupervisorFenceScopeAndTransfer(t *testing.T) {
	options, alive, identity := fixtureOptions(t)
	first, _ := NewSupervisor(options)
	second, _ := NewSupervisor(options)
	ctx, p := supervisorActor(t, "alice")
	scope := Scope{AllowedBundles: []string{"fixture.app"}}
	lease, err := first.Acquire(ctx, p, scope)
	if err != nil {
		t.Fatal(err)
	}
	lease.Scope.AllowedBundles[0] = "forged" // no alias to internal scope
	if _, err = second.Acquire(ctx, p, scope); !errors.Is(err, ErrContended) {
		t.Fatalf("competing input fence: %v", err)
	}
	if _, err = first.Lease(ctx, p); !errors.Is(err, ErrNoLease) {
		t.Fatal("helper-less lease dispatch authority")
	}
	if err = first.AttachHelper(ctx, p, identity, func(context.Context) (CleanupReport, error) {
		*alive = false
		return CleanupReport{InputInhibited: true, HelperStopped: true}, nil
	}); err != nil {
		t.Fatal(err)
	}
	held, err := first.Lease(ctx, p)
	if err != nil || held.Scope.AllowedBundles[0] != "fixture.app" {
		t.Fatalf("held: %+v %v", held, err)
	}
	otherCtx, other := supervisorActor(t, "bob")
	if _, err = first.Lease(otherCtx, other); err == nil {
		t.Fatal("cross-user input admitted")
	}
	report, err := first.Close(ctx)
	if err != nil || !report.HelperStopped || !report.FenceReleased {
		t.Fatalf("cleanup: %+v %v", report, err)
	}
	next, err := second.Acquire(ctx, p, scope)
	if err != nil || next.Generation != 2 {
		t.Fatalf("epoch transfer: %+v %v", next, err)
	}
	_, _ = second.Close(ctx)
}
func TestSupervisorOldHelperAndPIDReuse(t *testing.T) {
	options, alive, identity := fixtureOptions(t)
	old := record{Generation: 7, Helper: &identity}
	data, _ := json.Marshal(old)
	if err := os.WriteFile(options.LockPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	supervisor, _ := NewSupervisor(options)
	ctx, p := supervisorActor(t, "alice")
	if _, err := supervisor.Acquire(ctx, p, Scope{AllowedBundles: []string{"fixture.app"}}); !errors.Is(err, ErrOldHelperAlive) {
		t.Fatalf("old input authority transferred: %v", err)
	}
	*alive = false
	lease, err := supervisor.Acquire(ctx, p, Scope{AllowedBundles: []string{"fixture.app"}})
	if err != nil || lease.Generation != 8 {
		t.Fatalf("stopped proof: %+v %v", lease, err)
	}
	_, _ = supervisor.Close(ctx)
}
func TestSupervisorBoundedStopRetainsFence(t *testing.T) {
	options, alive, identity := fixtureOptions(t)
	s, _ := NewSupervisor(options)
	ctx, p := supervisorActor(t, "alice")
	_, err := s.Acquire(ctx, p, Scope{AllowedBundles: []string{"fixture.app"}})
	if err != nil {
		t.Fatal(err)
	}
	unblock := make(chan struct{})
	defer close(unblock)
	if err = s.AttachHelper(ctx, p, identity, func(context.Context) (CleanupReport, error) { <-unblock; return CleanupReport{}, nil }); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	report, err := s.Close(bounded)
	if !errors.Is(err, context.DeadlineExceeded) || report.FenceReleased || !report.UnknownInputs || report.InputInhibited {
		t.Fatalf("unsafe cleanup: %+v %v", report, err)
	}
	second, _ := NewSupervisor(options)
	if _, err = second.Acquire(ctx, p, Scope{AllowedBundles: []string{"fixture.app"}}); !errors.Is(err, ErrContended) {
		t.Fatal("failed teardown released physical fence")
	}
	s.file.Close()
	// Simulate broker descriptor loss and later helper exit. The durable unknown
	// barrier must survive even when OS flock and old liveness no longer block.
	*alive = false
	restarted, _ := NewSupervisor(options)
	if _, err = restarted.Acquire(ctx, p, Scope{AllowedBundles: []string{"fixture.app"}}); !errors.Is(err, ErrCleanupUnknown) {
		t.Fatalf("uncertain teardown disappeared after broker loss: %v", err)
	}
}

func TestSupervisorStopErrorPersistsUnknownCleanup(t *testing.T) {
	options, alive, identity := fixtureOptions(t)
	s, _ := NewSupervisor(options)
	ctx, p := supervisorActor(t, "alice")
	if _, err := s.Acquire(ctx, p, Scope{AllowedBundles: []string{"fixture.app"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AttachHelper(ctx, p, identity, func(context.Context) (CleanupReport, error) {
		return CleanupReport{InputInhibited: true}, errors.New("fixture teardown failure")
	}); err != nil {
		t.Fatal(err)
	}
	report, err := s.Close(ctx)
	if err == nil || !report.UnknownInputs || report.FenceReleased {
		t.Fatalf("unsafe stop error: %+v %v", report, err)
	}
	_ = s.file.Close()
	*alive = false
	restarted, _ := NewSupervisor(options)
	if _, err = restarted.Acquire(ctx, p, Scope{AllowedBundles: []string{"fixture.app"}}); !errors.Is(err, ErrCleanupUnknown) {
		t.Fatalf("failed stop lost durable barrier: %v", err)
	}
}
func TestSupervisorUnsafePathsAndCorruptRecords(t *testing.T) {
	options, _, _ := fixtureOptions(t)
	ctx, p := supervisorActor(t, "alice")
	if err := os.WriteFile(options.LockPath, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewSupervisor(options)
	if _, err := s.Acquire(ctx, p, Scope{AllowedBundles: []string{"fixture.app"}}); err == nil {
		t.Fatal("corrupt epoch accepted")
	}
	_ = os.Remove(options.LockPath)
	target := filepath.Join(filepath.Dir(options.LockPath), "target")
	_ = os.WriteFile(target, []byte(""), 0600)
	_ = os.Symlink(target, options.LockPath)
	if _, err := s.Acquire(ctx, p, Scope{AllowedBundles: []string{"fixture.app"}}); err == nil {
		t.Fatal("symlink input fence accepted")
	}
}

func TestUnknownCleanupBlocksNextEpoch(t *testing.T) {
	options, alive, identity := fixtureOptions(t)
	ctx, p := supervisorActor(t, "alice")
	s, _ := NewSupervisor(options)
	scope := Scope{AllowedBundles: []string{"fixture.app"}}
	if _, err := s.Acquire(ctx, p, scope); err != nil {
		t.Fatal(err)
	}
	if err := s.AttachHelper(ctx, p, identity, func(context.Context) (CleanupReport, error) {
		*alive = false
		return CleanupReport{InputInhibited: true, HelperStopped: true, UnknownInputs: true}, nil
	}); err != nil {
		t.Fatal(err)
	}
	report, err := s.Close(ctx)
	if err != nil || !report.UnknownInputs {
		t.Fatalf("cleanup evidence: %+v %v", report, err)
	}
	next, _ := NewSupervisor(options)
	if _, err = next.Acquire(ctx, p, scope); !errors.Is(err, ErrCleanupUnknown) {
		t.Fatalf("unresolved held input silently accepted: %v", err)
	}
}
