package consent_test

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mechanize/consent"
)

func TestDispatchCleanupRecoveryRetainsApprovalOnlyAfterHostProof(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		proofFails, humanStop bool
	}{
		{name: "stopped executors"}, {name: "proof unavailable", proofFails: true}, {name: "human stop", humanStop: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			g := grant(t, f, consent.AllowUntilRevoked)
			op := operation(g)
			lease, err := f.service.Authorize(f.client, op)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.service.ReportDispatchCleanupUnknown(f.client, g.ID); err != nil {
				t.Fatal(err)
			}
			lease.Release()
			if tc.humanStop {
				if _, err = f.service.Revoke(f.admin, g.ID); err != nil {
					t.Fatal(err)
				}
				if _, err = f.service.CleanupUnknown(f.admin, g.ID); err != nil {
					t.Fatal(err)
				}
			}
			proofs := 0
			options := f.options
			options.RecoverCleanup = func(context.Context, consent.Client, consent.Scope) error {
				proofs++
				if tc.proofFails {
					return errors.New("original executor still alive")
				}
				return nil
			}
			restarted, err := consent.New(options)
			if err != nil {
				t.Fatal(err)
			}
			err = restarted.RecoverDispatchCleanup(f.client, g.ID)
			if tc.proofFails || tc.humanStop {
				if tc.humanStop && proofs != 0 {
					t.Fatal("human stop invoked recovery callback")
				}
				if err == nil {
					t.Fatal("recovery restored unsafe or explicitly withdrawn approval")
				}
				if found, _ := restarted.FindPermanentGrant(f.client, op); found != nil {
					t.Fatal("failed recovery enabled input")
				}
				return
			}
			if err != nil || proofs != 1 {
				t.Fatalf("recovery: proofs=%d err=%v", proofs, err)
			}
			found, err := restarted.FindPermanentGrant(f.client, op)
			if err != nil || found == nil || found.ID != g.ID || found.Scope != g.Scope || found.Decision != g.Decision {
				t.Fatalf("existing approval changed: %+v %v", found, err)
			}
		})
	}
}

func TestDispatchCleanupRecoveryDoesNotTrustEmptyRegistryWithoutProof(t *testing.T) {
	f := newFixture(t)
	g := grant(t, f, consent.AllowUntilRevoked)
	lease, err := f.service.Authorize(f.client, operation(g))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, err = f.service.ReportDispatchCleanupUnknown(f.client, g.ID); err != nil {
		t.Fatal(err)
	}
	restarted, err := consent.New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.RecoverDispatchCleanup(f.client, g.ID); !errors.Is(err, consent.ErrCleanupUnconfirmed) {
		t.Fatalf("empty registry became cleanup proof: %v", err)
	}
}

func TestDispatchCleanupRecoveryCannotRaceHumanRevocation(t *testing.T) {
	f := newFixture(t)
	g := grant(t, f, consent.AllowUntilRevoked)
	lease, err := f.service.Authorize(f.client, operation(g))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.ReportDispatchCleanupUnknown(f.client, g.ID); err != nil {
		t.Fatal(err)
	}
	lease.Release()
	options := f.options
	options.RecoverCleanup = func(context.Context, consent.Client, consent.Scope) error {
		_, err := f.service.Revoke(f.admin, g.ID)
		return err
	}
	restarted, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.RecoverDispatchCleanup(f.client, g.ID); err == nil {
		t.Fatal("recovery overwrote concurrent human stop")
	}
	if found, _ := restarted.FindPermanentGrant(f.client, operation(g)); found != nil {
		t.Fatal("concurrent human stop was lost")
	}
}

func TestDispatchCleanupGuardSpansCASAndNeverReplaysFailedCommit(t *testing.T) {
	for _, mode := range []string{"confirmed", "missingProof", "humanStop", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			g := suspendedDesktopGrant(t, f)
			options := f.options
			entered, commits := 0, 0
			options.WithCleanupProof = func(ctx context.Context, _ consent.Client, _ consent.Scope, commit func(context.Context) error) error {
				entered++
				if mode == "missingProof" {
					return consent.ErrCleanupUnconfirmed
				}
				if mode == "humanStop" {
					if _, err := f.service.Revoke(f.admin, g.ID); err != nil {
						return err
					}
				}
				if mode == "canceled" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				commits++
				return commit(ctx)
			}
			// A failed sealed proof must never fall back to another commit attempt.
			options.RecoverCleanup = func(context.Context, consent.Client, consent.Scope) error {
				t.Fatal("guard failure replayed through legacy recovery")
				return nil
			}
			restarted, err := consent.New(options)
			if err != nil {
				t.Fatal(err)
			}
			err = restarted.RecoverDispatchCleanup(f.client, g.ID)
			if (err == nil) != (mode == "confirmed") || entered != 1 || commits > 1 {
				t.Fatalf("mode%s entered%d commits%d err%v", mode, entered, commits, err)
			}
			if mode == "confirmed" {
				lease, err := restarted.Authorize(f.client, operation(g))
				if err != nil {
					t.Fatal("recovered authority unavailable", err)
				}
				lease.Release()
			}
		})
	}
}
