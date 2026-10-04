package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/session"
)

func competingReconciliationSupervisor(t *testing.T, f *controlFixture) *session.Supervisor {
	t.Helper()
	supervisor, err := session.NewSupervisor(session.Options{
		LockPath: f.options.LockPath, HelperExecutable: f.options.HelperPath,
		Inspect: func(int) (session.ProcessIdentity, bool, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.identity, f.alive, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = supervisor.Close(context.Background()) })
	return supervisor
}

func TestHoldReconciliationFenceFreshDoesNotStartHelperAndExcludesCompetitor(t *testing.T) {
	f := newControlFixture(t)
	release, err := f.manager.holdReconciliationFence(f.ctx, f.principal)
	if err != nil || release == nil {
		t.Fatalf("fresh reconciliation fence unavailable: release=%v err=%v", release != nil, err)
	}
	defer func() {
		if err := release(); err != nil {
			t.Errorf("release reconciliation fence: %v", err)
		}
	}()
	if f.starts != 0 || f.calls != 0 || f.manager.held != nil {
		t.Fatalf("fresh guard created or dispatched through helper: starts=%d calls=%d held=%v", f.starts, f.calls, f.manager.held != nil)
	}
	competitor := competingReconciliationSupervisor(t, f)
	scope := session.Scope{AllowedBundles: []string{"com.fixture.app"}}
	if _, err := competitor.Acquire(f.ctx, f.principal, scope); !errors.Is(err, session.ErrContended) {
		t.Fatalf("competing supervisor acquired held fence: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release fence: %v", err)
	}
	if _, err := competitor.Acquire(f.ctx, f.principal, scope); err != nil {
		t.Fatalf("competitor could not acquire after release: %v", err)
	}
}

func TestHoldReconciliationFenceCleansExistingHelperBeforeReadFence(t *testing.T) {
	f := newControlFixture(t)
	f.admit(t)
	if !f.alive || f.starts != 1 {
		t.Fatalf("fixture helper was not admitted: alive=%v starts=%d", f.alive, f.starts)
	}
	release, err := f.manager.holdReconciliationFence(f.ctx, f.principal)
	if err != nil || release == nil {
		t.Fatalf("reconciliation fence unavailable: release=%v err=%v", release != nil, err)
	}
	defer func() {
		if err := release(); err != nil {
			t.Errorf("release reconciliation fence: %v", err)
		}
	}()
	if f.alive || f.starts != 1 || f.calls != 0 || f.manager.held != nil {
		t.Fatalf("old helper was not cleaned before read fence: alive=%v starts=%d calls=%d held=%v", f.alive, f.starts, f.calls, f.manager.held != nil)
	}
	competitor := competingReconciliationSupervisor(t, f)
	scope := session.Scope{AllowedBundles: []string{"com.fixture.app"}}
	if _, err := competitor.Acquire(f.ctx, f.principal, scope); !errors.Is(err, session.ErrContended) {
		t.Fatalf("read fence was not held after helper cleanup: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release read fence: %v", err)
	}
	if _, err := competitor.Acquire(f.ctx, f.principal, scope); err != nil {
		t.Fatalf("competitor could not acquire after read fence release: %v", err)
	}
}

func TestHoldReconciliationFenceRetainsUnknownCleanupBarrier(t *testing.T) {
	f := newControlFixture(t)
	f.admit(t)
	f.unknown = true
	if _, err := f.manager.holdReconciliationFence(f.ctx, f.principal); !errors.Is(err, ErrNativeControlCleanupUnknown) {
		t.Fatalf("unknown helper cleanup admitted read fence: %v", err)
	}
	if f.manager.held == nil || !f.manager.held.inhibited {
		t.Fatal("uncertain helper cleanup did not retain inhibited helper state")
	}
	contents, err := os.ReadFile(f.options.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Lease       *session.Lease           `json:"lease"`
		Helper      *session.ProcessIdentity `json:"helper"`
		LastCleanup *session.CleanupReport   `json:"lastCleanup"`
	}
	if err := json.Unmarshal(contents, &record); err != nil {
		t.Fatal(err)
	}
	if record.Lease == nil || record.Helper == nil || record.LastCleanup == nil || !record.LastCleanup.UnknownInputs || record.LastCleanup.FenceReleased {
		t.Fatalf("uncertain cleanup barrier was not persisted: %+v", record)
	}
	// Resolve only the test fixture's simulated cleanup after asserting the retained barrier.
	f.unknown = false
	if _, err := f.manager.Close(context.Background()); err != nil {
		t.Fatalf("fixture cleanup after barrier assertion: %v", err)
	}
}

func TestHoldReconciliationFenceRejectsForeignPrincipalWithExistingHelper(t *testing.T) {
	f := newControlFixture(t)
	f.admit(t)
	foreign, err := auth.NewPrincipal("foreign-issuer", "foreign-tenant", "other", []string{"desktop:control"})
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Namespace == f.principal.Namespace {
		t.Fatal("foreign fixture unexpectedly shares namespace")
	}
	foreignCtx := auth.WithPrincipal(context.Background(), foreign)
	if _, err := f.manager.holdReconciliationFence(foreignCtx, foreign); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("foreign principal acquired another client's helper fence: %v", err)
	}
	if f.manager.held == nil || !f.alive {
		t.Fatal("foreign request changed the current helper state")
	}
}
