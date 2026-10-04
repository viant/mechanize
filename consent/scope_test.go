package consent_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/viant/mechanize/consent"
)

func TestDesktopScopeCoversOnlyValidatedTargets(t *testing.T) {
	desktop := consent.Scope{Kind: "desktop"}
	for _, target := range []consent.Scope{{Kind: "application", BundleID: "com.example.Mail"}, {Kind: "application", BundleID: "com.example.Browser"}, {Kind: "window", BundleID: "com.example.Editor", WindowID: "42"}, {Kind: "origin", Origin: "https://example.com"}, {Kind: "desktop"}} {
		if !desktop.Covers(target) {
			t.Fatalf("desktop did not cover %+v", target)
		}
		if target.Kind != "desktop" && target.Covers(desktop) {
			t.Fatalf("narrow scope expanded to desktop: %+v", target)
		}
	}
	for _, target := range []consent.Scope{{Kind: "desktop", BundleID: "com.example.Mail"}, {Kind: "desktop", WindowID: "42"}, {Kind: "desktop", Origin: "https://example.com"}, {Kind: "application", BundleID: "*"}, {Kind: "origin", Origin: "https://*.example.com"}, {Kind: "window", BundleID: "com.example.Mail"}, {Kind: "unknown"}} {
		if target.Validate() == nil || desktop.Covers(target) || target.Covers(desktop) {
			t.Fatalf("invalid target covered: %+v", target)
		}
	}
	exact := consent.Scope{Kind: "window", BundleID: "com.example.Mail", WindowID: "42", DisplayName: "Old label"}
	renamed := exact
	renamed.DisplayName = "New label"
	if !exact.Covers(renamed) {
		t.Fatal("presentation label changed authority")
	}
	for _, target := range []consent.Scope{{Kind: "application", BundleID: exact.BundleID}, {Kind: "window", BundleID: exact.BundleID, WindowID: "43"}, {Kind: "window", BundleID: "com.example.Other", WindowID: "42"}, {Kind: "origin", Origin: "https://example.com"}} {
		if exact.Covers(target) {
			t.Fatalf("exact scope widened %+v", target)
		}
	}
}

func desktopGrant(t *testing.T, f *fixture, modes []consent.Mode, decision consent.Decision) *consent.Grant {
	t.Helper()
	request, err := f.service.CreateRequest(f.client, "fixture-session", consent.RequestInput{Scope: consent.Scope{Kind: "desktop", DisplayName: "Desktop"}, Modes: modes, Purpose: "Work across my desktop", DurationSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Decide(f.client, request.ID, decision); err == nil {
		t.Fatal("tool approved desktop access")
	}
	g, err := f.service.Decide(f.admin, request.ID, decision)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func desktopOperation(g *consent.Grant, target consent.Scope, mode consent.Mode) consent.Operation {
	op := operation(g)
	op.Scope = target
	op.Mode = mode
	return op
}

func TestGeneratedDesktopApprovalAcrossApplicationsAndOrigin(t *testing.T) {
	f := newFixture(t)
	g := desktopGrant(t, f, []consent.Mode{consent.Observe, consent.Control}, consent.AllowSession)
	targets := []consent.Scope{{Kind: "application", BundleID: "com.example.Mail"}, {Kind: "application", BundleID: "com.example.Editor"}, {Kind: "window", BundleID: "com.example.Editor", WindowID: "42"}, {Kind: "origin", Origin: "https://example.com"}}
	for _, target := range targets {
		for _, mode := range []consent.Mode{consent.Observe, consent.Control} {
			lease, err := f.service.Authorize(f.client, desktopOperation(g, target, mode))
			if err != nil {
				t.Fatalf("%+v %s: %v", target, mode, err)
			}
			lease.Release()
		}
	}
	for _, mode := range []consent.Mode{consent.Record, "unexpected"} {
		if _, err := f.service.Authorize(f.client, desktopOperation(g, targets[0], mode)); err == nil {
			t.Fatalf("unapproved mode %s", mode)
		}
	}
	bad := desktopOperation(g, targets[0], consent.Control)
	bad.Purpose = "Different purpose"
	if _, err := f.service.Authorize(f.client, bad); err == nil {
		t.Fatal("desktop widened purpose")
	}
	bad = desktopOperation(g, targets[0], consent.Control)
	bad.SessionID = "other-session"
	if _, err := f.service.Authorize(f.client, bad); err == nil {
		t.Fatal("desktop widened session")
	}
	options := f.options
	options.VerifyClient = func(context.Context) (consent.Client, error) {
		return consent.Client{ID: "other-client", SessionID: "fixture-session", Verification: "verified", DisplayName: "Other"}, nil
	}
	other, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.Authorize(f.client, desktopOperation(g, targets[0], consent.Control)); err == nil {
		t.Fatal("desktop widened client")
	}
	options = f.options
	options.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	expired, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = expired.Authorize(f.client, desktopOperation(g, targets[0], consent.Control)); err == nil {
		t.Fatal("desktop grant remained active after expiry")
	}
	rows, err := f.service.ListGrants(f.admin)
	if err != nil || len(rows) != 1 || rows[0].Scope.Kind != "desktop" {
		t.Fatalf("persisted desktop grant: %+v %v", rows, err)
	}
}

func TestGeneratedDesktopObserveDoesNotAuthorizeControlOrRecord(t *testing.T) {
	f := newFixture(t)
	g := desktopGrant(t, f, []consent.Mode{consent.Observe}, consent.AllowSession)
	target := consent.Scope{Kind: "application", BundleID: "com.example.Mail"}
	for _, mode := range []consent.Mode{consent.Control, consent.Record} {
		if _, err := f.service.Authorize(f.client, desktopOperation(g, target, mode)); err == nil {
			t.Fatalf("observe approval granted %s", mode)
		}
	}
}

func TestGeneratedDesktopRechecksResolvedTargetPolicy(t *testing.T) {
	f := newFixture(t)
	g := desktopGrant(t, f, []consent.Mode{consent.Control}, consent.AllowSession)
	options := f.options
	options.Policy = func(_ context.Context, _ consent.Client, scope consent.Scope, _ []consent.Mode, _ int) error {
		if scope.BundleID == "com.example.Restricted" {
			return errors.New("target ceiling")
		}
		return nil
	}
	service, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Authorize(f.client, desktopOperation(g, consent.Scope{Kind: "application", BundleID: "com.example.Restricted"}, consent.Control)); err == nil {
		t.Fatal("desktop skipped concrete target ceiling")
	}
}

func TestGeneratedDesktopOnceCASCoversOnlyOneTarget(t *testing.T) {
	f := newFixture(t)
	g := desktopGrant(t, f, []consent.Mode{consent.Control}, consent.AllowOnce)
	other, err := consent.New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, service := range []*consent.Service{f.service, other} {
		wg.Add(1)
		go func(i int, s *consent.Service) {
			defer wg.Done()
			target := consent.Scope{Kind: "application", BundleID: []string{"com.example.Mail", "com.example.Editor"}[i]}
			lease, err := s.Authorize(f.client, desktopOperation(g, target, consent.Control))
			if err == nil {
				lease.Release()
			}
			results <- err
		}(i, service)
	}
	wg.Wait()
	close(results)
	allowed := 0
	for err := range results {
		if err == nil {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("once CAS winners=%d", allowed)
	}
}

func TestGeneratedDesktopStopCancelsEveryCoveredTarget(t *testing.T) {
	f := newFixture(t)
	g := desktopGrant(t, f, []consent.Mode{consent.Control}, consent.AllowSession)
	var leases []*consent.Lease
	for _, bundle := range []string{"com.example.Mail", "com.example.Editor"} {
		lease, err := f.service.Authorize(f.client, desktopOperation(g, consent.Scope{Kind: "application", BundleID: bundle}, consent.Control))
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, lease)
		defer lease.Release()
	}
	state, err := f.service.Revoke(f.admin, g.ID)
	if err != nil || state != consent.Requested {
		t.Fatalf("stop=%s %v", state, err)
	}
	for _, lease := range leases {
		if lease.Context.Err() == nil {
			t.Fatal("desktop stop missed admitted target")
		}
		lease.Release()
	}
	if _, err = f.service.Authorize(f.client, desktopOperation(g, consent.Scope{Kind: "origin", Origin: "https://example.com"}, consent.Control)); err == nil {
		t.Fatal("desktop stop allowed a new connected origin")
	}
}
