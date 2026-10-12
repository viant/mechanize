package data

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

func TestPreflightLifecycleSealIsOnlyExactZeroChildClosure(t *testing.T) {
	p, e := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control", "desktop:observe"})
	if e != nil {
		t.Fatal(e)
	}
	p.ClientID = "successor"
	p.ClientName = "Successor"
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx, e = WithScope(ctx, Scope{Namespace: p.Namespace})
	if e != nil {
		t.Fatal(e)
	}
	binding := auth.ConsentBinding{SessionID: "current-session", GrantID: "current-grant", Purpose: "current preparation"}
	ctx = auth.WithConsentBinding(ctx, binding)
	old := CredentialProtectionScopeRecord{Namespace: p.Namespace, ClientID: "controller:" + strings.Repeat("a", 64), PreparationID: strings.Repeat("b", 64), Origin: "https://fixture.invalid"}
	valid := &atomic.Bool{}
	valid.Store(true)
	guard := func(c context.Context) error {
		if !valid.Load() {
			return errors.New("proof no longer valid")
		}
		return c.Err()
	}
	sealed, revoke, e := WithCredentialPreflightLifecycleAuthority(ctx, old, guard)
	if e != nil {
		t.Fatal(e)
	}
	defer revoke()
	actual, _ := auth.FromContext(sealed)
	if actual.ClientID != p.ClientID {
		t.Fatal("seal changed actual actor")
	}
	before := CredentialPreparationRecord{Namespace: old.Namespace, ClientID: old.ClientID, SessionID: "old-session", PreparationID: old.PreparationID, GrantID: "old-grant", PurposeHash: CredentialDeliveryPurposeHash("old login"), Origin: old.Origin, SelectedRevision: strings.Repeat("c", 64), ProtectionState: "held", Revision: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	clean, stop, e := WithCredentialPreflightCleanupAuthority(sealed, before, guard)
	if e != nil {
		t.Fatal(e)
	}
	defer stop()
	closed := before
	closed.ProtectionState = "closed"
	closed.Revision++
	bound, release, e := WithCredentialPreparationAuthority(clean, closed, guard)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if _, e = RequireCredentialPreparationAuthority(bound); e != nil {
		t.Fatal(e)
	}
	// Neither the lifecycle read seal nor the zero-child cleanup can reserve
	// another preparation or create/resolve any delivery attempt.
	for _, c := range []context.Context{sealed, clean, bound} {
		attempt := CredentialDeliveryRecord{Namespace: old.Namespace, ClientID: old.ClientID, SelectionID: old.PreparationID, ProtectionState: "held", DispatchState: "unknown"}
		if _, _, e := WithCredentialDeliveryAuthority(c, CredentialDeliveryAuthority{Record: attempt}, guard); e == nil {
			t.Fatal("lifecycle seal granted delivery")
		}
		if _, _, e := WithCredentialPreparationAuthority(c, before, guard); e == nil && c == sealed {
			t.Fatal("read seal granted original reservation")
		}
		if _, _, e := WithCredentialSourceAbsenceAuthority(c, before, []CredentialDeliveryRecord{attempt}, nil, guard); e == nil {
			t.Fatal("preflight seal granted exact/UNKNOWN cleanup")
		}
		if _, _, e := WithCredentialCleanupAuthority(c, before, nil, guard); e == nil {
			t.Fatal("preflight seal granted generic original cleanup")
		}
	}
	for _, kind := range []string{"preparation", "client", "namespace", "origin"} {
		changed := before
		switch kind {
		case "preparation":
			changed.PreparationID = strings.Repeat("d", 64)
		case "client":
			changed.ClientID = "controller:" + strings.Repeat("d", 64)
		case "namespace":
			changed.Namespace = strings.Repeat("d", 64)
		case "origin":
			changed.Origin = "https://other.invalid"
		}
		if _, _, e := WithCredentialPreflightCleanupAuthority(sealed, changed, guard); e == nil {
			t.Fatal("scope altered", kind)
		}
	}
	for _, kind := range []string{"actor", "binding", "canceled", "revoked"} {
		c := bound
		switch kind {
		case "actor":
			q := p
			q.ClientID = "other"
			c = auth.WithPrincipal(c, q)
		case "binding":
			b := binding
			b.GrantID = "other"
			c = auth.WithConsentBinding(c, b)
		case "canceled":
			var cancel context.CancelFunc
			c, cancel = context.WithCancel(c)
			cancel()
		case "revoked":
			valid.Store(false)
		}
		if _, e := RequireCredentialPreparationAuthority(c); e == nil {
			t.Fatal("stale seal admitted", kind)
		}
		valid.Store(true)
	}
	revoke()
	if _, e := RequireCredentialPreparationAuthority(bound); e == nil {
		t.Fatal("released lifecycle seal remained active")
	}
}
