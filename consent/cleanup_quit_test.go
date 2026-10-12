package consent_test

import (
	"testing"

	"github.com/viant/mechanize/consent"
)

func TestCleanupQuitUsesExistingDesktopApprovalButCannotAuthorizeOtherActions(t *testing.T) {
	f := newFixture(t)
	in := input()
	in.Scope = consent.Scope{Kind: "desktop"}
	r, err := f.service.CreateRequest(f.client, "fixture-session", in)
	if err != nil {
		t.Fatal(err)
	}
	g, err := f.service.Decide(f.admin, r.ID, consent.AllowUntilRevoked)
	if err != nil {
		t.Fatal(err)
	}
	op := operation(g)
	active, err := f.service.Authorize(f.client, op)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Release()
	if _, err = f.service.ReportDispatchCleanupUnknown(f.client, g.ID); err != nil {
		t.Fatal(err)
	}
	op.Scope = consent.Scope{Kind: "application", BundleID: "com.google.Chrome"}
	cleanup, id, err := f.service.AuthorizeCleanupQuit(f.client, op)
	if err != nil || id != g.ID {
		t.Fatalf("approved shutdown unavailable: %s %v", id, err)
	}
	defer cleanup.Release()
	if _, err = f.service.Authorize(f.client, op); err == nil {
		t.Fatal("cleanup authorization restored ordinary input")
	}
	bad := op
	bad.Scope.BundleID = "com.example.Other"
	if _, _, err = f.service.AuthorizeCleanupQuit(f.client, bad); err == nil {
		t.Fatal("cleanup widened target")
	}
	bad = op
	bad.Mode = consent.Observe
	if _, _, err = f.service.AuthorizeCleanupQuit(f.client, bad); err == nil {
		t.Fatal("cleanup authorized reading")
	}
	if _, err = f.service.Revoke(f.admin, g.ID); err != nil {
		t.Fatal(err)
	}
	if cleanup.Context.Err() == nil {
		t.Fatal("human stop did not cancel cleanup")
	}
	if _, err = f.service.CleanupUnknown(f.admin, g.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.service.AuthorizeCleanupQuit(f.client, op); err == nil {
		t.Fatal("human stop was bypassed")
	}
	restarted, err := consent.New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = restarted.AuthorizeCleanupQuit(f.client, op); err == nil {
		t.Fatal("restart lost human stop history")
	}
}

func TestBoundCleanupUnknownGenericErrorHidesSupportedQuitAuthority(t *testing.T) {
	f := newFixture(t)
	in := input()
	in.Scope = consent.Scope{Kind: "desktop"}
	request, e := f.service.CreateRequest(f.client, "fixture-session", in)
	if e != nil {
		t.Fatal(e)
	}
	g, e := f.service.Decide(f.admin, request.ID, consent.AllowUntilRevoked)
	if e != nil {
		t.Fatal(e)
	}
	op := operation(g)
	lease, e := f.service.Authorize(f.client, op)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.ReportDispatchCleanupUnknown(f.client, g.ID); e != nil {
		t.Fatal(e)
	}
	lease.Release()
	op.Scope = consent.Scope{Kind: "application", BundleID: "com.google.Chrome"}
	_, ordinary := f.service.Authorize(f.client, op)
	if ordinary == nil || ordinary.Error() != "active bound consent required" {
		t.Fatal("expected bound-grant blocked branch")
	}
	cleanup, id, e := f.service.AuthorizeCleanupQuit(f.client, op)
	if e != nil || id != g.ID {
		t.Fatal("supported exact cleanup authority unavailable", e)
	}
	cleanup.Release()
}
