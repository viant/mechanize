package consent_test

import (
	"context"
	"errors"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	service       *consent.Service
	options       consent.Options
	client, admin context.Context
	deny          bool
}
type actorKey struct{}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(file))
	scope := data.Scope{Namespace: strings.Repeat("c", 64), LeaseEpoch: 1}
	ctx, err := data.WithScope(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	server, err := datahost.Open(ctx, root, t.TempDir(), scope)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	f := &fixture{client: ctx, admin: context.WithValue(ctx, actorKey{}, true)}
	c := consent.Client{ID: "fixture-agent", DisplayName: "Fixture Agent", Verification: "verified", SessionID: "fixture-session"}
	f.options = consent.Options{Namespace: scope.Namespace, Invoke: server.InvokeComponent, VerifyClient: func(context.Context) (consent.Client, error) { return c, nil }, ResolveClient: func(context.Context, string, string) (consent.Client, error) { return c, nil }, VerifyActor: func(ctx context.Context) (consent.Actor, error) {
		if ctx.Value(actorKey{}) != true {
			return consent.Actor{}, errors.New("tool cannot decide")
		}
		return consent.Actor{ID: "fixture-human", Human: true, Admin: true}, nil
	}, Policy: func(context.Context, consent.Client, consent.Scope, []consent.Mode, int) error {
		if f.deny {
			return errors.New("operator ceiling")
		}
		return nil
	}}
	f.service, err = consent.New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func input() consent.RequestInput {
	return consent.RequestInput{Scope: consent.Scope{Kind: "window", BundleID: "com.example.Editor", WindowID: "42", DisplayName: "Draft"}, Modes: []consent.Mode{consent.Observe, consent.Control}, Purpose: "Edit this draft", DurationSeconds: 60}
}
func operation(g *consent.Grant) consent.Operation {
	return consent.Operation{GrantID: g.ID, SessionID: "fixture-session", Scope: g.Scope, Mode: consent.Control, Purpose: g.Purpose}
}
func grant(t *testing.T, f *fixture, decision consent.Decision) *consent.Grant {
	t.Helper()
	request, err := f.service.CreateRequest(f.client, "fixture-session", input())
	if err != nil {
		t.Fatal(err)
	}
	g, err := f.service.Decide(f.admin, request.ID, decision)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func TestGeneratedConsentOnceAndActorBoundary(t *testing.T) {
	f := newFixture(t)
	request, err := f.service.CreateRequest(f.client, "fixture-session", input())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Decide(f.client, request.ID, consent.AllowOnce); err == nil {
		t.Fatal("LLM tool approved grant")
	}
	rows, err := f.service.ListRequests(f.admin)
	if err != nil || len(rows) != 1 {
		t.Fatalf("requests: %+v %v", rows, err)
	}
	g, err := f.service.Decide(f.admin, request.ID, consent.AllowOnce)
	if err != nil {
		t.Fatal(err)
	}
	if g.ClientID != "fixture-agent" || g.Scope != input().Scope || g.Purpose != input().Purpose || g.DurationSeconds != 60 {
		t.Fatalf("grant widened %+v", g)
	}
	if _, err = f.service.Decide(f.admin, request.ID, consent.AllowSession); err == nil {
		t.Fatal("decision replay")
	}
	bad := operation(g)
	bad.Scope.WindowID = "43"
	if _, err = f.service.Authorize(f.client, bad); err == nil {
		t.Fatal("target widened")
	}
	lease, err := f.service.Authorize(f.client, operation(g))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, err = f.service.Authorize(f.client, operation(g)); err == nil {
		t.Fatal("once reused")
	}
	grants, err := f.service.ListGrants(f.admin)
	if err != nil || len(grants) != 1 || grants[0].State != "consumed" {
		t.Fatalf("grants %+v %v", grants, err)
	}
}

func TestDispatchUncertaintyInhibitsWithoutHumanImpersonation(t *testing.T) {
	f := newFixture(t)
	g := grant(t, f, consent.AllowSession)
	if _, err := f.service.ReportDispatchCleanupUnknown(f.client, g.ID); err == nil {
		t.Fatal("unadmitted client marked a grant uncertain")
	}
	lease, err := f.service.Authorize(f.client, operation(g))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, err = f.service.ReportDispatchCleanupUnknown(f.client, "foreign-grant"); err == nil {
		t.Fatal("foreign grant changed")
	}
	state, err := f.service.ReportDispatchCleanupUnknown(f.client, g.ID)
	if err != nil || state != consent.CleanupUnknown {
		t.Fatalf("uncertainty not durable: %s %v", state, err)
	}
	if lease.Context.Err() == nil {
		t.Fatal("uncertain dispatch remains uninhibited")
	}
	if _, err = f.service.Authorize(f.client, operation(g)); err == nil {
		t.Fatal("uncertain grant admitted new input")
	}
	if state, err = f.service.ReportDispatchCleanupUnknown(f.client, g.ID); err != nil || state != consent.CleanupUnknown {
		t.Fatalf("repeated report: %s %v", state, err)
	}
	if _, err = f.service.Decide(f.client, g.RequestID, consent.AllowSession); err == nil {
		t.Fatal("cleanup client approved consent")
	}
	restarted, err := consent.New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Authorize(f.client, operation(g)); err == nil {
		t.Fatal("restart bypassed persisted uncertainty")
	}
}
func TestGeneratedConsentCASAcrossBrokerInstances(t *testing.T) {
	f := newFixture(t)
	g := grant(t, f, consent.AllowOnce)
	other, err := consent.New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, service := range []*consent.Service{f.service, other} {
		wg.Add(1)
		go func(s *consent.Service) {
			defer wg.Done()
			lease, err := s.Authorize(f.client, operation(g))
			if err == nil {
				lease.Release()
			}
			results <- err
		}(service)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("CAS winners %d", success)
	}
}
func TestGeneratedConsentRevocationStopsAndWaitsForCleanup(t *testing.T) {
	f := newFixture(t)
	g := grant(t, f, consent.AllowSession)
	lease, err := f.service.Authorize(f.client, operation(g))
	if err != nil {
		t.Fatal(err)
	}
	state, err := f.service.Revoke(f.admin, g.ID)
	if err != nil || state != consent.Requested {
		t.Fatalf("%s %v", state, err)
	}
	if _, err = f.service.Authorize(f.client, operation(g)); err == nil {
		t.Fatal("requested revoke allowed input")
	}
	state, err = f.service.Revoke(f.admin, g.ID)
	if err != nil || state != consent.Stopping {
		t.Fatalf("%s %v", state, err)
	}
	select {
	case <-lease.Context.Done():
	case <-time.After(time.Second):
		t.Fatal("cancellation not delivered")
	}
	state, err = f.service.Revoke(f.admin, g.ID)
	if err != nil || state != consent.Stopping {
		t.Fatalf("premature cleanup %s %v", state, err)
	}
	lease.Release()
	state, err = f.service.Revoke(f.admin, g.ID)
	if err != nil || state != consent.Revoked {
		t.Fatalf("%s %v", state, err)
	}
	grants, err := f.service.ListGrants(f.admin)
	if err != nil || grants[0].State != "revoked" {
		t.Fatalf("%+v %v", grants, err)
	}
}
func TestConsentRestartDoesNotInventCleanup(t *testing.T) {
	f := newFixture(t)
	g := grant(t, f, consent.AllowSession)
	restarted, err := consent.New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []consent.RevocationState{consent.Requested, consent.Stopping, consent.CleanupUnknown} {
		state, err := restarted.Revoke(f.admin, g.ID)
		if err != nil || state != want {
			t.Fatalf("want %s got %s: %v", want, state, err)
		}
	}
}
func TestConsentBoundIdentityPolicyTimeAndDeny(t *testing.T) {
	f := newFixture(t)
	otherScope, err := data.WithScope(f.client, data.Scope{Namespace: strings.Repeat("d", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.CreateRequest(otherScope, "fixture-session", input()); err == nil {
		t.Fatal("fixed consent connector accepted another namespace")
	}
	forgedOptions := f.options
	forgedOptions.VerifyClient = func(context.Context) (consent.Client, error) {
		return consent.Client{ID: "forged", DisplayName: "Forged Agent", Verification: "unverified", SessionID: "fixture-session"}, nil
	}
	forged, err := consent.New(forgedOptions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = forged.CreateRequest(f.client, "fixture-session", input()); err == nil {
		t.Fatal("unverified client manufactured request")
	}
	if _, err := f.service.CreateRequest(f.client, "forged-session", input()); err == nil {
		t.Fatal("session forged")
	}
	g := grant(t, f, consent.AllowSession)
	f.deny = true
	if _, err := f.service.Authorize(f.client, operation(g)); err == nil {
		t.Fatal("grant elevated operator ceiling")
	}
	f.deny = false
	bad := operation(g)
	bad.SessionID = "other-session"
	if _, err := f.service.Authorize(f.client, bad); err == nil {
		t.Fatal("session binding absent")
	}
	if g := grant(t, f, consent.Deny); g != nil {
		t.Fatal("deny manufactured grant")
	}
	options := f.options
	options.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	expired, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = expired.Authorize(f.client, operation(g)); err == nil {
		t.Fatal("expired grant active")
	}
	if _, err = consent.New(consent.Options{}); err == nil {
		t.Fatal("missing broker accepted")
	}
}

func TestConsentInvalidScopeAndDuration(t *testing.T) {
	for _, scope := range []consent.Scope{{Kind: "window", BundleID: "com.example.Editor"}, {Kind: "application", BundleID: "com.example.Editor", WindowID: "42"}, {Kind: "origin", Origin: "https://user:secret@example.com"}, {Kind: "origin", Origin: "https://example.com/path"}, {Kind: "origin", Origin: "https://example.com?"}, {Kind: "origin", Origin: "file://example.com"}} {
		if scope.Validate() == nil {
			t.Fatalf("invalid exact target accepted: %+v", scope)
		}
	}
}
