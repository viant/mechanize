package vault

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"testing"
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
