package vault

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"strings"
	"testing"
	"time"
)

func TestRetiredDeliveryRecoveryKeepsBarrierUntilTrustedRetirementFinishes(t *testing.T) {
	for _, mode := range []string{"gone", "alive", "ledgerFailure", "foreign", "active", "busy", "lateFailure"} {
		t.Run(mode, func(t *testing.T) {
			g := deliveryGate(t)
			ctx := deliveryContext()
			l, e := g.BeginDelivery(ctx, fixtureBinding(), func(context.Context) error { return nil }, func(context.Context) error { return ErrEntryCleanup })
			if e != nil {
				t.Fatal(e)
			}
			if mode != "active" {
				l.Retire()
			}
			if mode == "busy" {
				l.inFlight = 1
			}
			if mode == "foreign" {
				p, _ := auth.FromContext(ctx)
				p.ClientID = "foreign"
				ctx = auth.WithPrincipal(ctx, p)
			}
			calls, proofs := 0, 0
			e = l.RecoverRetired(ctx, func(context.Context) error {
				proofs++
				if mode == "alive" || mode == "lateFailure" && proofs == 2 {
					return errors.New("not gone")
				}
				return nil
			}, func(context.Context) error {
				calls++
				if _, e := g.AcquireExposure(); !errors.Is(e, ErrDeliveryProtected) {
					t.Fatal("barrier released before ledger")
				}
				if mode == "ledgerFailure" {
					return errors.New("ledger unavailable")
				}
				return nil
			})
			if (e == nil) != (mode == "gone") {
				t.Fatal("incorrect recovery", mode)
			}
			release, blocked := g.AcquireExposure()
			if mode == "gone" {
				if blocked != nil {
					t.Fatal(blocked)
				}
				release()
			} else if !errors.Is(blocked, ErrDeliveryProtected) {
				t.Fatal("failed cleanup released barrier")
			}
			if (mode == "alive" || mode == "foreign" || mode == "active" || mode == "busy") && calls != 0 {
				t.Fatal("unproved cleanup reached ledger")
			}
		})
	}
}

func TestIdleForeignProtectionReleaseRequiresExactCompleteSourceSeal(t *testing.T) {
	for _, kind := range []string{"complete", "metadataOnly", "wrongTarget", "revoked", "consentChanged", "busy"} {
		t.Run(kind, func(t *testing.T) {
			ctx := deliveryContext()
			old, _ := auth.FromContext(ctx)
			old.ClientID = "controller:" + strings.Repeat("a", 64)
			ctx = auth.WithPrincipal(ctx, old)
			binding := fixtureBinding()
			binding.Target.Account = strings.Repeat("b", 64)
			gate := deliveryGate(t)
			lease, e := gate.BeginDelivery(ctx, binding, func(context.Context) error { return nil }, func(context.Context) error { return nil })
			if e != nil {
				t.Fatal(e)
			}
			successor := old
			successor.ClientID = "successor"
			current := auth.WithPrincipal(context.Background(), successor)
			current = auth.WithConsentBinding(current, auth.ConsentBinding{SessionID: "current", GrantID: "current-grant", Purpose: "current"})
			current, e = data.WithScope(current, data.Scope{Namespace: old.Namespace})
			if e != nil {
				t.Fatal(e)
			}
			scope := data.CredentialProtectionScopeRecord{Namespace: old.Namespace, ClientID: old.ClientID, PreparationID: binding.Target.Account, Origin: binding.Target.Origin, ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, DocumentID: binding.DocumentID, DocumentGeneration: 1, ChromeStartToken: "original-birth", BrokerEpoch: "original", ChannelEpoch: "original", ScopeHash: strings.Repeat("c", 64), LoginRouteSHA256: strings.Repeat("d", 64), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
			valid := true
			guard := func(c context.Context) error {
				if !valid {
					return data.ErrCredentialDeliveryAuthority
				}
				return c.Err()
			}
			sealed, revoke, e := data.WithCredentialSourceLifecycleAuthority(current, scope, guard)
			if e != nil {
				t.Fatal(e)
			}
			defer revoke()
			original, _ := auth.ConsentBindingFromContext(ctx)
			prep := data.CredentialPreparationRecord{Namespace: old.Namespace, ClientID: old.ClientID, PreparationID: scope.PreparationID, SessionID: binding.SessionID, GrantID: original.GrantID, PurposeHash: data.CredentialDeliveryPurposeHash(original.Purpose), Origin: scope.Origin, SelectedRevision: strings.Repeat("e", 64), ProtectionState: "held", Revision: 1, CreatedAt: scope.CreatedAt}
			clean, stop, e := data.WithCredentialSourceAbsenceAuthority(sealed, prep, nil, []data.CredentialProtectionScopeRecord{scope}, guard)
			if e != nil {
				t.Fatal(e)
			}
			defer stop()
			switch kind {
			case "metadataOnly":
				clean = sealed
			case "wrongTarget":
				lease.binding.Target.Account = strings.Repeat("f", 64)
			case "revoked":
				valid = false
			case "consentChanged":
				clean = auth.WithConsentBinding(clean, auth.ConsentBinding{SessionID: "other", GrantID: "current-grant", Purpose: "current"})
			case "busy":
				lease.inFlight = 1
			}
			called := false
			e = lease.RecoverRetired(clean, guard, func(context.Context) error { called = true; return nil })
			if (e == nil) != (kind == "complete") || called != (kind == "complete") {
				t.Fatal("incorrect sealed recovery", kind)
			}
			if kind == "complete" {
				release, e := gate.AcquireExposureContext(current)
				if e != nil {
					t.Fatal(e)
				}
				release()
			} else if _, e := gate.AcquireExposureContext(current); !errors.Is(e, ErrDeliveryProtected) {
				t.Fatal("failed cleanup released protection")
			}
			if e = lease.WithDelivery(current, binding, func() error { t.Fatal("foreign delivery permitted"); return nil }); e == nil {
				t.Fatal("cleanup transferred delivery")
			}
		})
	}
}
