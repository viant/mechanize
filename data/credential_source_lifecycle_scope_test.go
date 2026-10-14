package data

import (
	"context"
	"github.com/viant/mechanize/auth"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSourceLifecycleSealRetiresOnlyOriginalProtection(t *testing.T) {
	testSourceLifecycleSeal(t, "controller:"+strings.Repeat("a", 64))
}

func TestNonControllerSourceLifecycleSealPreservesUnknown(t *testing.T) {
	testSourceLifecycleSeal(t, "synthetic-operator")
}

func testSourceLifecycleSeal(t *testing.T, sourceClient string) {
	p, _ := auth.NewPrincipal("fixture", "", "lifecycle", []string{"desktop:control"})
	p.ClientID = "successor"
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx, e := WithScope(ctx, Scope{Namespace: p.Namespace})
	if e != nil {
		t.Fatal(e)
	}
	binding := auth.ConsentBinding{SessionID: "current", GrantID: "grant", Purpose: "current preparation"}
	ctx = auth.WithConsentBinding(ctx, binding)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	scope := CredentialProtectionScopeRecord{Namespace: p.Namespace, ClientID: sourceClient, PreparationID: strings.Repeat("b", 64), Origin: "https://fixture.invalid", ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, DocumentID: "old-document", DocumentGeneration: 1, ChromeStartToken: "old-birth", BrokerEpoch: "old-broker", ChannelEpoch: "old-channel", ScopeHash: strings.Repeat("c", 64), LoginRouteSHA256: strings.Repeat("d", 64), CreatedAt: now}
	valid := atomic.Bool{}
	valid.Store(true)
	guard := func(c context.Context) error {
		if !valid.Load() {
			return ErrCredentialDeliveryAuthority
		}
		return c.Err()
	}
	sealed, revoke, e := WithCredentialSourceLifecycleAuthority(ctx, scope, guard)
	if e != nil {
		t.Fatal(e)
	}
	defer revoke()
	prep := CredentialPreparationRecord{Namespace: p.Namespace, ClientID: scope.ClientID, PreparationID: scope.PreparationID, SessionID: "old", GrantID: "old-grant", PurposeHash: CredentialDeliveryPurposeHash("old"), Origin: scope.Origin, SelectedRevision: strings.Repeat("e", 64), ProtectionState: "held", Revision: 1, CreatedAt: now}
	attempt := CredentialDeliveryRecord{Namespace: p.Namespace, ClientID: prep.ClientID, SessionID: prep.SessionID, SelectionID: prep.PreparationID, GrantID: prep.GrantID, PurposeHash: prep.PurposeHash, SelectedRevision: prep.SelectedRevision, Origin: scope.Origin, AttemptID: strings.Repeat("f", 64), ChromeStartToken: scope.ChromeStartToken, ProfileChannel: scope.ProfileChannel, BrowserInstance: scope.BrowserInstance, TabID: scope.TabID, DocumentID: scope.DocumentID, DispatchState: "unknown", ProtectionState: "held", Revision: 1, CreatedAt: now, UpdatedAt: now}
	if actual, _ := auth.FromContext(sealed); actual.ClientID != p.ClientID {
		t.Fatal("original principal impersonated")
	}
	for _, makeSeal := range []func() (context.Context, func(), error){
		func() (context.Context, func(), error) {
			return WithCredentialPreparationAuthority(sealed, prep, guard)
		},
		func() (context.Context, func(), error) {
			return WithCredentialDeliveryAuthority(sealed, CredentialDeliveryAuthority{Record: attempt}, guard)
		},
		func() (context.Context, func(), error) {
			return WithCredentialCleanupAuthority(sealed, prep, []CredentialDeliveryRecord{attempt}, guard)
		},
		func() (context.Context, func(), error) {
			return WithCredentialRetirementAuthority(sealed, prep, []CredentialDeliveryRecord{attempt}, scope.ChromeStartToken, guard)
		},
	} {
		if _, _, err := makeSeal(); err == nil {
			t.Fatal("metadata seal granted delivery/reservation or generic cleanup")
		}
	}
	clean, stop, e := WithCredentialSourceAbsenceAuthority(sealed, prep, []CredentialDeliveryRecord{attempt}, []CredentialProtectionScopeRecord{scope}, guard)
	if e != nil {
		t.Fatal(e)
	}
	defer stop()
	next := attempt
	next.ProtectionState = "retired"
	next.Revision++
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	bound, release, e := WithCredentialDeliveryAuthority(clean, CredentialDeliveryAuthority{Before: &attempt, Record: next}, guard)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if got, err := RequireCredentialDeliveryAuthority(bound); err != nil || got.Record.DispatchState != "unknown" || got.Record.ClientID != scope.ClientID {
		t.Fatal("retirement changed original UNKNOWN ownership")
	}
	for _, kind := range []string{"dispatch", "attempt", "client", "selection"} {
		bad := next
		switch kind {
		case "dispatch":
			bad.DispatchState = "notDispatched"
		case "attempt":
			bad.AttemptID = strings.Repeat("0", 64)
		case "client":
			bad.ClientID = p.ClientID
		case "selection":
			bad.SelectionID = strings.Repeat("0", 64)
		}
		if _, _, err := WithCredentialDeliveryAuthority(clean, CredentialDeliveryAuthority{Before: &attempt, Record: bad}, guard); err == nil {
			t.Fatal("immutable delivery changed", kind)
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
		if _, err := RequireCredentialDeliveryAuthority(c); err == nil {
			t.Fatal("stale lifecycle authority survived", kind)
		}
		valid.Store(true)
	}
	revoke()
	if _, err := RequireCredentialDeliveryAuthority(bound); err == nil {
		t.Fatal("released lifecycle authority survived")
	}
}
