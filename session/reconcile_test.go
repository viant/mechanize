package session

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"os"
	"testing"
)

func TestReconcileUnusedRequiresExactOwnerGenerationAndLedgerProof(t *testing.T) {
	options, alive, identity := fixtureOptions(t)
	*alive = false
	ctx, p := supervisorActor(t, "alice")
	lease := Lease{ID: "fixture", Generation: 7, Owner: p.Namespace, Scope: Scope{AllApplications: true}}
	prior := record{Generation: 7, Lease: &lease, Helper: &identity, LastCleanup: &CleanupReport{UnknownInputs: true}}
	raw, _ := json.Marshal(prior)
	if err := os.WriteFile(options.LockPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewSupervisor(options)
	proofCalls := 0
	proof := func(context.Context, auth.Principal, uint64) error { proofCalls++; return nil }
	if _, err := s.ReconcileUnused(ctx, p, 8, proof); err == nil || proofCalls != 0 {
		t.Fatal("wrong generation reconciled")
	}
	otherCtx, other := supervisorActor(t, "bob")
	if _, err := s.ReconcileUnused(otherCtx, other, 7, proof); err == nil || proofCalls != 0 {
		t.Fatal("foreign owner reconciled")
	}
	denial := errors.New("ledger intent present")
	if _, err := s.ReconcileUnused(ctx, p, 7, func(context.Context, auth.Principal, uint64) error { return denial }); !errors.Is(err, ErrCleanupUnknown) {
		t.Fatal("intent did not retain barrier")
	}
	*alive = true
	if _, err := s.ReconcileUnused(ctx, p, 7, proof); !errors.Is(err, ErrOldHelperAlive) {
		t.Fatal("live helper reconciled")
	}
	*alive = false
	report, err := s.ReconcileUnused(ctx, p, 7, proof)
	if err != nil || !report.FenceReleased || report.UnknownInputs || proofCalls != 1 {
		t.Fatalf("unused reconciliation: %+v %v", report, err)
	}
	fresh, _ := NewSupervisor(options)
	next, err := fresh.Acquire(ctx, p, Scope{AllApplications: true})
	if err != nil || next.Generation != 8 {
		t.Fatalf("transfer: %+v %v", next, err)
	}
	_, _ = fresh.Close(ctx)
}

func TestReconcileNoRawInputRequiresHistoricalProfileAndExactStoppedGeneration(t *testing.T) {
	for _, profile := range []InputProfile{"", InputProfileRaw, InputProfileSemantic, InputProfileLaunch} {
		t.Run(string(profile), func(t *testing.T) {
			options, alive, identity := fixtureOptions(t)
			*alive = false
			ctx, p := supervisorActor(t, "alice")
			lease := Lease{ID: "historical", Generation: 20, Owner: p.Namespace, Scope: Scope{AllApplications: true}}
			prior := record{Generation: 20, Lease: &lease, Helper: &identity, InputProfile: profile, LastCleanup: &CleanupReport{UnknownInputs: true}}
			raw, _ := json.Marshal(prior)
			if err := os.WriteFile(options.LockPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			s, _ := NewSupervisor(options)
			if _, err := s.ReconcileNoRawInput(ctx, p, 21); !errors.Is(err, ErrCleanupUnknown) {
				t.Fatal("wrong generation accepted")
			}
			otherCtx, other := supervisorActor(t, "bob")
			if _, err := s.ReconcileNoRawInput(otherCtx, other, 20); !errors.Is(err, ErrCleanupUnknown) {
				t.Fatal("foreign owner accepted")
			}
			*alive = true
			if _, err := s.ReconcileNoRawInput(ctx, p, 20); !errors.Is(err, ErrOldHelperAlive) {
				t.Fatal("live helper accepted")
			}
			*alive = false
			report, err := s.ReconcileNoRawInput(ctx, p, 20)
			if profile == "" || profile == InputProfileRaw {
				if !errors.Is(err, ErrCleanupUnknown) {
					t.Fatalf("unproven raw input exclusion: %v", err)
				}
				after, _ := os.ReadFile(options.LockPath)
				if string(after) != string(raw) {
					t.Fatal("failed recovery changed barrier")
				}
				return
			}
			if err != nil || report.UnknownInputs || !report.InputInhibited || !report.HelperStopped || !report.FenceReleased || !report.BusinessOutcomeUnknown {
				t.Fatalf("physical-only recovery: %+v %v", report, err)
			}
			after, _ := os.ReadFile(options.LockPath)
			var saved record
			if json.Unmarshal(after, &saved) != nil || saved.Helper != nil || saved.Lease != nil || !saved.LastCleanup.BusinessOutcomeUnknown {
				t.Fatal("business uncertainty lost")
			}
			next, err := s.Acquire(ctx, p, Scope{AllApplications: true})
			if err != nil || next.Generation != 21 {
				t.Fatalf("transfer: %+v %v", next, err)
			}
			_, _ = s.Close(ctx)
		})
	}
}

func TestReconcileNoRawInputRequiresTwoStopProofs(t *testing.T) {
	options, _, identity := fixtureOptions(t)
	ctx, p := supervisorActor(t, "alice")
	lease := Lease{ID: "historical", Generation: 20, Owner: p.Namespace, Scope: Scope{AllApplications: true}}
	prior := record{Generation: 20, Lease: &lease, Helper: &identity, InputProfile: InputProfileSemantic, LastCleanup: &CleanupReport{UnknownInputs: true}}
	raw, _ := json.Marshal(prior)
	if err := os.WriteFile(options.LockPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	options.Inspect = func(int) (ProcessIdentity, bool, error) { calls++; return identity, calls > 1, nil }
	s, _ := NewSupervisor(options)
	if _, err := s.ReconcileNoRawInput(ctx, p, 20); !errors.Is(err, ErrOldHelperAlive) || calls != 2 {
		t.Fatalf("lost second stop proof: %v calls=%d", err, calls)
	}
	after, _ := os.ReadFile(options.LockPath)
	if string(after) != string(raw) {
		t.Fatal("changed barrier after second stop proof failed")
	}
}

func TestReconcileNeverDispatchedPreservesFenceOnIncompleteOriginalOutcomeProof(t *testing.T) {
	options, alive, identity := fixtureOptions(t)
	*alive = false
	ctx, p := supervisorActor(t, "alice")
	lease := Lease{ID: "historical", Generation: 22, Owner: p.Namespace, Scope: Scope{AllApplications: true}}
	prior := record{Generation: 22, Lease: &lease, Helper: &identity, LastCleanup: &CleanupReport{UnknownInputs: true, BusinessOutcomeUnknown: true}}
	raw, _ := json.Marshal(prior)
	if err := os.WriteFile(options.LockPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewSupervisor(options)
	denied := errors.New("original pre-dispatch evidence unavailable")
	if _, err := s.ReconcileNeverDispatched(ctx, p, 22, func(context.Context, auth.Principal, uint64) error { return denied }); !errors.Is(err, ErrCleanupUnknown) {
		t.Fatal("incomplete proof released barrier")
	}
	after, _ := os.ReadFile(options.LockPath)
	if string(after) != string(raw) {
		t.Fatal("rejected proof changed historical barrier")
	}
	*alive = true
	calls := 0
	proof := func(_ context.Context, owner auth.Principal, generation uint64) error {
		calls++
		if owner.Namespace != p.Namespace || generation != 22 {
			t.Fatal("callback scope changed")
		}
		return nil
	}
	if _, err := s.ReconcileNeverDispatched(ctx, p, 22, proof); !errors.Is(err, ErrOldHelperAlive) || calls != 0 {
		t.Fatal("live helper reached outcome proof")
	}
	*alive = false
	report, err := s.ReconcileNeverDispatched(ctx, p, 22, proof)
	if err != nil || report.UnknownInputs || !report.FenceReleased || !report.HelperStopped || !report.BusinessOutcomeUnknown || calls != 1 {
		t.Fatalf("physical-only recovery: %+v %v", report, err)
	}
}
