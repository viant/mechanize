package consent_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/viant/mechanize/consent"
)

func TestRepeatedRequestsReusePendingWithoutApproving(t *testing.T) {
	f := newFixture(t)
	const count = 6
	ids := make(chan string, count)
	failures := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := f.service.RequestOrReuse(f.client, "fixture-session", input())
			if e != nil {
				failures <- e
				return
			}
			if r.ExistingGrant != nil {
				failures <- context.Canceled
				return
			}
			ids <- r.ID
		}()
	}
	wg.Wait()
	close(ids)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		}
		if id != first {
			t.Fatal("duplicate consent prompts")
		}
	}
	rows, err := f.service.ListRequests(f.admin)
	if err != nil || len(rows) != 1 {
		t.Fatalf("pending=%d err=%v", len(rows), err)
	}
	grants, err := f.service.ListGrants(f.admin)
	if err != nil || len(grants) != 0 {
		t.Fatal("request created approval")
	}
	in := input()
	in.Scope.DisplayName = "Same editor"
	in.Modes = []consent.Mode{consent.Control, consent.Observe}
	r, err := f.service.RequestOrReuse(f.client, "fixture-session", in)
	if err != nil || r.ID != first {
		t.Fatal("presentation label or mode order created duplicate prompt")
	}
}

func TestRequestReusesPermanentTrustAcrossSessionsAndPurpose(t *testing.T) {
	f := newFixture(t)
	g := grant(t, f, consent.AllowUntilRevoked)
	s := permanentSession(t, f, "fixture-agent", "new-session")
	in := input()
	in.Purpose = "Another task"
	r, err := s.RequestOrReuse(f.client, "new-session", in)
	if err != nil || r.ExistingGrant == nil || r.ExistingGrant.ID != g.ID {
		t.Fatalf("grant not reused: %+v %v", r, err)
	}
	rows, err := s.ListRequests(f.admin)
	if err != nil || len(rows) != 0 {
		t.Fatal("permanent trust created new prompt")
	}
	other := permanentSession(t, f, "another-client", "new-session")
	r, err = other.RequestOrReuse(f.client, "new-session", in)
	if err != nil || r.ExistingGrant != nil {
		t.Fatalf("other client inherited trust: %+v %v", r, err)
	}
	f.deny = true
	if _, err = s.RequestOrReuse(f.client, "new-session", in); err == nil {
		t.Fatal("current operator policy bypassed")
	}
}

func TestRequestReusesSessionWithoutExtendingIt(t *testing.T) {
	f := newFixture(t)
	g := grant(t, f, consent.AllowSession)
	r, err := f.service.RequestOrReuse(f.client, "fixture-session", input())
	if err != nil || r.ExistingGrant == nil || r.ExistingGrant.ID != g.ID || !r.ExistingGrant.ExpiresAt.Equal(g.ExpiresAt) {
		t.Fatalf("session grant changed: %+v %v", r, err)
	}
	in := input()
	in.Purpose = "Other purpose"
	r, err = f.service.RequestOrReuse(f.client, "fixture-session", in)
	if err != nil || r.ExistingGrant != nil {
		t.Fatal("session purpose broadened")
	}
}

func TestRequestReuseDoesNotBroadenScopeOrModes(t *testing.T) {
	for _, mode := range []string{"scope", "modes", "once"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			decision := consent.AllowUntilRevoked
			if mode == "once" {
				decision = consent.AllowOnce
			}
			g := grant(t, f, decision)
			in := input()
			if mode == "scope" {
				in.Scope.WindowID = "43"
			}
			if mode == "modes" {
				in.Modes = append(in.Modes, consent.Record)
			}
			r, err := f.service.RequestOrReuse(f.client, "fixture-session", in)
			if err != nil || r.ExistingGrant != nil || r.ID == g.RequestID {
				t.Fatalf("scope widened or once reused: %+v %v", r, err)
			}
		})
	}
}

func TestRequestReuseRequiresAllModesAndDoesNotRenewPendingExpiry(t *testing.T) {
	f := newFixture(t)
	in := input()
	in.Modes = []consent.Mode{consent.Observe}
	first, err := f.service.CreateRequest(f.client, "fixture-session", in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Decide(f.admin, first.ID, consent.AllowUntilRevoked); err != nil {
		t.Fatal(err)
	}
	full := grant(t, f, consent.AllowUntilRevoked)
	r, err := f.service.RequestOrReuse(f.client, "fixture-session", input())
	if err != nil || r.ExistingGrant == nil || r.ExistingGrant.ID != full.ID {
		t.Fatalf("selected insufficient modes: %+v %v", r, err)
	}

	f = newFixture(t)
	now := time.Now()
	options := f.options
	options.Now = func() time.Time { return now }
	s, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	first, err = s.RequestOrReuse(f.client, "fixture-session", input())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	r, err = s.RequestOrReuse(f.client, "fixture-session", input())
	if err != nil || r.ID != first.ID || !r.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("pending expiry extended")
	}
	now = now.Add(2 * time.Minute)
	r, err = s.RequestOrReuse(f.client, "fixture-session", input())
	if err != nil || r.ID == first.ID || r.ExistingGrant != nil {
		t.Fatal("expired request reused or approved")
	}
}
