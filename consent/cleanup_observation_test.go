package consent_test

import (
	"github.com/viant/mechanize/consent"
	"testing"
)

func TestMachineCleanupRetainsApprovedObservationButNeverRestoresControl(t *testing.T) {
	f := newFixture(t)
	g := grant(t, f, consent.AllowUntilRevoked)
	op := operation(g)
	active, err := f.service.Authorize(f.client, op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.ReportDispatchCleanupUnknown(f.client, g.ID); err != nil {
		t.Fatal(err)
	}
	active.Release()
	op.Mode = consent.Observe
	observed, err := f.service.Authorize(f.client, op)
	if err != nil {
		t.Fatal("approved observation unavailable", err)
	}
	defer observed.Release()
	found, err := f.service.FindPermanentGrant(f.client, op)
	if err != nil || found == nil || found.ID != g.ID {
		t.Fatal(found, err)
	}
	control := op
	control.Mode = consent.Control
	if _, err = f.service.Authorize(f.client, control); err == nil {
		t.Fatal("observation restored input")
	}
	if _, _, err = f.service.AuthorizeCleanupObservation(f.client, control); err == nil {
		t.Fatal("cleanup observation widened mode")
	}
	foreign := op
	foreign.Scope.BundleID = "com.other.App"
	if _, _, err = f.service.AuthorizeCleanupObservation(f.client, foreign); err == nil {
		t.Fatal("observation widened scope")
	}
	if _, err = f.service.Revoke(f.admin, g.ID); err != nil {
		t.Fatal(err)
	}
	if observed.Context.Err() == nil {
		t.Fatal("human stop did not cancel observation")
	}
	if _, err = f.service.CleanupUnknown(f.admin, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.service.AuthorizeCleanupObservation(f.client, op); err == nil {
		t.Fatal("human stop bypassed")
	}
	restarted, err := consent.New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = restarted.AuthorizeCleanupObservation(f.client, op); err == nil {
		t.Fatal("restart erased human stop history")
	}
}

func TestCleanupObservationRequiresPermanentApprovedObservationMode(t *testing.T) {
	for _, decision := range []consent.Decision{consent.AllowOnce, consent.AllowSession, consent.AllowUntilRevoked} {
		t.Run(string(decision), func(t *testing.T) {
			f := newFixture(t)
			in := input()
			in.Modes = []consent.Mode{consent.Control}
			if decision != consent.AllowUntilRevoked {
				in.Modes = []consent.Mode{consent.Observe, consent.Control}
			}
			request, err := f.service.CreateRequest(f.client, "fixture-session", in)
			if err != nil {
				t.Fatal(err)
			}
			g, err := f.service.Decide(f.admin, request.ID, decision)
			if err != nil {
				t.Fatal(err)
			}
			active, err := f.service.Authorize(f.client, operation(g))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.service.ReportDispatchCleanupUnknown(f.client, g.ID); err != nil {
				t.Fatal(err)
			}
			active.Release()
			op := operation(g)
			op.Mode = consent.Observe
			if _, _, err = f.service.AuthorizeCleanupObservation(f.client, op); err == nil {
				t.Fatal("unapproved observation allowed")
			}
		})
	}
}
