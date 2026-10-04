package data

import (
	"context"
	"github.com/viant/mechanize/auth"
	"sync"
	"testing"
)

func committedIntentFixture(t *testing.T) (context.Context, auth.Principal, CommittedStepIntent) {
	t.Helper()
	p, _ := auth.NewPrincipal("fixture", "", "owner", nil)
	p.ClientID = "client"
	ctx, _ := WithScope(auth.WithPrincipal(context.Background(), p), Scope{Namespace: p.Namespace, LeaseEpoch: 7})
	return ctx, p, CommittedStepIntent{Namespace: p.Namespace, ClientID: p.ClientID, RunID: "run", PlanID: "plan", StepID: "step", StepIndex: 0, AttemptID: "attempt", EffectID: "effect", LeaseEpoch: 7, RunRevision: 2, SessionID: "session", OperationID: "operation"}
}
func TestCommittedStepIntentScalarCopyAndRevocation(t *testing.T) {
	ctx, p, r := committedIntentFixture(t)
	bound, revoke, e := WithCommittedStepIntent(ctx, p, r)
	if e != nil {
		t.Fatal(e)
	}
	r.AttemptID = "changed"
	got, e := RequireCommittedStepIntent(bound, p)
	if e != nil || got.AttemptID != "attempt" {
		t.Fatal("record not copied", got, e)
	}
	got.EffectID = "changed"
	again, e := RequireCommittedStepIntent(bound, p)
	if e != nil || again.EffectID != "effect" {
		t.Fatal("returned record aliases authority")
	}
	if _, e = RequireCommittedStepIntent(WithoutCommittedStepIntent(bound), p); e == nil {
		t.Fatal("read-only context inherited mutation proof")
	}
	if _, e = RequireCommittedStepIntent(bound, p); e != nil {
		t.Fatal("read-only mask revoked parent proof", e)
	}
	revoke()
	revoke()
	if _, e = RequireCommittedStepIntent(context.WithoutCancel(bound), p); e == nil {
		t.Fatal("captured context stayed active")
	}
	if _, e = RequireCommittedStepIntent(ctx, p); e == nil {
		t.Fatal("plain record created proof")
	}
}
func TestCommittedStepIntentRejectsIdentityScopeAndInvalidRecords(t *testing.T) {
	for _, mode := range []string{"actor", "client", "namespace", "scope", "epoch", "revision", "index", "missingID", "oversizeID", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, p, r := committedIntentFixture(t)
			switch mode {
			case "actor":
				foreign, _ := auth.NewPrincipal("fixture", "", "foreign", nil)
				ctx = auth.WithPrincipal(ctx, foreign)
			case "client":
				other := p
				other.ClientID = "foreign"
				ctx = auth.WithPrincipal(ctx, other)
			case "namespace":
				r.Namespace = "foreign"
			case "scope":
				ctx = auth.WithPrincipal(context.Background(), p)
			case "epoch":
				r.LeaseEpoch = 8
			case "revision":
				r.RunRevision = 0
			case "index":
				r.StepIndex = -1
			case "missingID":
				r.AttemptID = ""
			case "oversizeID":
				r.AttemptID = string(make([]byte, 257))
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, _, e := WithCommittedStepIntent(ctx, p, r); e == nil {
				t.Fatal("invalid proof minted")
			}
		})
	}
	ctx, p, r := committedIntentFixture(t)
	bound, revoke, e := WithCommittedStepIntent(ctx, p, r)
	if e != nil {
		t.Fatal(e)
	}
	defer revoke()
	other := p
	other.ClientID = "foreign"
	for _, bad := range []context.Context{auth.WithPrincipal(bound, other), func() context.Context {
		c, _ := WithScope(bound, Scope{Namespace: p.Namespace, LeaseEpoch: 8})
		return c
	}()} {
		if _, e = RequireCommittedStepIntent(bad, p); e == nil {
			t.Fatal("rebound proof accepted")
		}
	}
}
func TestCommittedStepIntentConcurrentRevocation(t *testing.T) {
	ctx, p, r := committedIntentFixture(t)
	bound, revoke, e := WithCommittedStepIntent(ctx, p, r)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = RequireCommittedStepIntent(bound, p)
			}
		}()
	}
	revoke()
	wg.Wait()
	if _, e = RequireCommittedStepIntent(bound, p); e == nil {
		t.Fatal("revoked proof accepted")
	}
}
