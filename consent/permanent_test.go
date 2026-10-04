package consent_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/consenttrusted"
)

func permanentSession(t *testing.T, f *fixture, id, session string) *consent.Service {
	t.Helper()
	options := f.options
	options.VerifyClient = func(context.Context) (consent.Client, error) {
		return consent.Client{ID: id, DisplayName: "Fixture Agent", Verification: "verified", SessionID: session}, nil
	}
	// A permanent authorization must never revive the original MCP session.
	options.ResolveClient = func(context.Context, string, string) (consent.Client, error) {
		return consent.Client{}, errors.New("old session closed")
	}
	options.Now = func() time.Time { return time.Now().Add(365 * 24 * time.Hour) }
	service, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestPermanentGrantRequiresHumanAndPersistsAcrossSessions(t *testing.T) {
	f := newFixture(t)
	in := input()
	in.Scope = consent.Scope{Kind: "desktop"}
	request, err := f.service.CreateRequest(f.client, "fixture-session", in)
	if err != nil {
		t.Fatal(err)
	}
	op := consent.Operation{SessionID: "fixture-session", Scope: consent.Scope{Kind: "application", BundleID: "com.fixture.Other"}, Mode: consent.Control, Purpose: "New task"}
	if g, err := f.service.FindPermanentGrant(f.client, op); err != nil || g != nil {
		t.Fatalf("request supplied approval: %+v %v", g, err)
	}
	if _, err = f.service.Decide(f.client, request.ID, consent.AllowUntilRevoked); err == nil {
		t.Fatal("tool approved permanent grant")
	}
	g, err := f.service.Decide(f.admin, request.ID, consent.AllowUntilRevoked)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Permanent || !g.ExpiresAt.Equal(time.UnixMilli(0)) || g.DurationSeconds != in.DurationSeconds {
		t.Fatalf("permanent metadata: %+v", g)
	}
	restarted := permanentSession(t, f, "fixture-agent", "fresh-session")
	op.SessionID = "fresh-session"
	found, err := restarted.FindPermanentGrant(f.client, op)
	if err != nil || found == nil || found.ID != g.ID {
		t.Fatalf("find on fresh session: %+v %v", found, err)
	}
	op.GrantID = found.ID
	parent, cancel := context.WithTimeout(f.client, time.Second)
	defer cancel()
	lease, err := restarted.Authorize(parent, op)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if deadline, ok := lease.Context.Deadline(); !ok || deadline.After(time.Now().Add(2*time.Second)) {
		t.Fatal("permanent lease lost caller deadline")
	}
	lease2, err := restarted.Authorize(f.client, op)
	if err != nil {
		t.Fatal(err)
	}
	defer lease2.Release()
	if _, ok := lease2.Context.Deadline(); ok {
		t.Fatal("permanent grant installed expiry deadline")
	}
	other := permanentSession(t, f, "other-agent", "fresh-session")
	if _, err = other.Authorize(f.client, op); err == nil {
		t.Fatal("other client used grant")
	}
	if found, err = other.FindPermanentGrant(f.client, op); err != nil || found != nil {
		t.Fatalf("other client discovered grant: %+v %v", found, err)
	}
	foreign, err := data.WithScope(f.client, data.Scope{Namespace: strings.Repeat("d", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Authorize(foreign, op); err == nil {
		t.Fatal("other namespace used grant")
	}
	if _, err = restarted.FindPermanentGrant(foreign, op); err == nil {
		t.Fatal("other namespace discovered grant")
	}
	f.deny = true
	if _, err = restarted.Authorize(f.client, op); err == nil {
		t.Fatal("permanent grant bypassed current policy")
	}
	if found, err = restarted.FindPermanentGrant(f.client, op); err != nil || found != nil {
		t.Fatalf("denied policy discovered grant: %+v %v", found, err)
	}
}

func TestPermanentGrantRetainsScopeModesAndRevokesAllSessions(t *testing.T) {
	f := newFixture(t)
	g := grant(t, f, consent.AllowUntilRevoked)
	current := consent.Client{ID: "fixture-agent", DisplayName: "Fixture Agent", Verification: "verified", SessionID: "session-one"}
	options := f.options
	options.VerifyClient = func(context.Context) (consent.Client, error) { return current, nil }
	options.ResolveClient = func(context.Context, string, string) (consent.Client, error) {
		return consent.Client{}, errors.New("old session closed")
	}
	service, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	op := operation(g)
	op.SessionID = current.SessionID
	op.Purpose = "different task"
	bad := op
	bad.Scope.WindowID = "43"
	if _, err = service.Authorize(f.client, bad); err == nil {
		t.Fatal("permanent grant widened target")
	}
	if found, err := service.FindPermanentGrant(f.client, bad); err != nil || found != nil {
		t.Fatalf("widened target discovered: %+v %v", found, err)
	}
	bad = op
	bad.Mode = consent.Record
	if _, err = service.Authorize(f.client, bad); err == nil {
		t.Fatal("permanent grant widened modes")
	}
	one, err := service.Authorize(f.client, op)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Release()
	current.SessionID = "session-two"
	op.SessionID = current.SessionID
	two, err := service.Authorize(f.client, op)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Release()
	if state, err := service.Revoke(f.admin, g.ID); err != nil || state != consent.Requested {
		t.Fatalf("revoke: %s %v", state, err)
	}
	if one.Context.Err() == nil || two.Context.Err() == nil {
		t.Fatal("revoke failed to cancel every bound session")
	}
	if _, err = service.Authorize(f.client, op); err == nil {
		t.Fatal("revoked grant admitted")
	}
	restarted := permanentSession(t, f, "fixture-agent", "session-two")
	if _, err = restarted.Authorize(f.client, op); err == nil {
		t.Fatal("restart forgot persisted revocation")
	}
	if found, err := restarted.FindPermanentGrant(f.client, op); err != nil || found != nil {
		t.Fatalf("restart discovered revoked grant: %+v %v", found, err)
	}
}

func TestZeroExpiryDoesNotMakeLegacyDecisionsPermanent(t *testing.T) {
	f := newFixture(t)
	for _, decision := range []consent.Decision{consent.AllowOnce, consent.AllowSession} {
		g := grant(t, f, decision)
		if g.Permanent || g.ExpiresAt.IsZero() {
			t.Fatalf("legacy grant metadata %+v", g)
		}
		restarted := permanentSession(t, f, "fixture-agent", "fixture-session")
		if _, err := restarted.Authorize(f.client, operation(g)); err == nil {
			t.Fatalf("%s survived expiry", decision)
		}
	}
}

func TestPermanentDiscoveryFailsClosedAtCandidateBound(t *testing.T) {
	f := newFixture(t)
	options := f.options
	original := options.Invoke
	options.Invoke = func(ctx context.Context, request exec.ComponentRequest) (any, error) {
		if request.Target.Component.Name == "consenttrusted" {
			rows := make([]*consenttrusted.Record, 257)
			return &consenttrusted.ListTrustedOutput{Data: rows}, nil
		}
		return original(ctx, request)
	}
	service, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.FindPermanentGrant(f.client, consent.Operation{SessionID: "fixture-session", Scope: input().Scope, Mode: consent.Control}); err == nil {
		t.Fatal("overflowing discovery silently selected grant")
	}
}

func TestPermanentCleanupReportRecognizesEveryAdmittedSession(t *testing.T) {
	f := newFixture(t)
	g := grant(t, f, consent.AllowUntilRevoked)
	current := consent.Client{ID: "fixture-agent", DisplayName: "Fixture Agent", Verification: "verified", SessionID: "one"}
	options := f.options
	options.VerifyClient = func(context.Context) (consent.Client, error) { return current, nil }
	service, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	op := operation(g)
	op.SessionID = current.SessionID
	one, err := service.Authorize(f.client, op)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Release()
	current.SessionID = "two"
	op.SessionID = current.SessionID
	two, err := service.Authorize(f.client, op)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Release()
	current.SessionID = "one"
	state, err := service.ReportDispatchCleanupUnknown(f.client, g.ID)
	if err != nil || state != consent.CleanupUnknown {
		t.Fatalf("first session lost its lease binding: %s %v", state, err)
	}
	if one.Context.Err() == nil || two.Context.Err() == nil {
		t.Fatal("cleanup uncertainty did not cancel both sessions")
	}
}
