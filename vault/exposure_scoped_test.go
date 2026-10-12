package vault

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestScopedWebExposureRetainsProtectionAndExcludesPrivateInput(t *testing.T) {
	g, ctx, b := deliveryGate(t), deliveryContext(), fixtureBinding()
	l, e := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	release, e := g.AcquireScopedWebExposure(ctx, func(_ context.Context, source Binding) error {
		if source != b {
			t.Fatal("wrong source")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = g.AcquireExposureContext(ctx); !errors.Is(e, ErrDeliveryProtected) {
		t.Fatal("ordinary exposure admitted")
	}
	if e = l.WithDelivery(ctx, b, func() error { t.Fatal("input dispatched"); return nil }); !errors.Is(e, ErrBusy) {
		t.Fatal(e)
	}
	release()
	release()
	if e = l.WithDelivery(ctx, b, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
}

func TestScopedWebExposureFailuresReleaseReservation(t *testing.T) {
	for _, kind := range []string{"deny", "panic", "cancel", "retire"} {
		t.Run(kind, func(t *testing.T) {
			g, ctx, b := deliveryGate(t), deliveryContext(), fixtureBinding()
			l, e := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil })
			if e != nil {
				t.Fatal(e)
			}
			scoped, cancel := context.WithCancel(ctx)
			defer cancel()
			release, e := g.AcquireScopedWebExposure(scoped, func(context.Context, Binding) error {
				switch kind {
				case "deny":
					return errors.New("private provider detail")
				case "panic":
					panic("private provider detail")
				case "cancel":
					cancel()
				case "retire":
					l.Retire()
				}
				return nil
			})
			if release != nil || !errors.Is(e, ErrDeliveryProtected) {
				t.Fatal("unsafe permit", e)
			}
			g.mu.Lock()
			readers := g.readers
			held := g.delivery == l
			g.mu.Unlock()
			if readers != 0 || !held {
				t.Fatal("reservation leak or protection lost")
			}
		})
	}
}

func TestScopedWebExposureReservationBlocksSourceChange(t *testing.T) {
	g, ctx, b := deliveryGate(t), deliveryContext(), fixtureBinding()
	l, e := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		release, e := g.AcquireScopedWebExposure(ctx, func(context.Context, Binding) error { close(entered); <-finish; return nil })
		if release != nil {
			release()
		}
		done <- e
	}()
	<-entered
	if e = l.WithDelivery(ctx, b, func() error { t.Error("private input overlapped proof"); return nil }); !errors.Is(e, ErrBusy) {
		t.Fatal(e)
	}
	l.Retire()
	close(finish)
	if e = <-done; !errors.Is(e, ErrDeliveryProtected) {
		t.Fatal("retired proof admitted", e)
	}
}

func TestScopedWebExposureNativeEntryRemainsGlobal(t *testing.T) {
	g := deliveryGate(t)
	ctx := fixtureContext("entry", true)
	l, e := g.Begin(ctx, fixtureBinding().Target, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close(ctx)
	called := false
	if _, e = g.AcquireScopedWebExposure(deliveryContext(), func(context.Context, Binding) error { called = true; return nil }); !errors.Is(e, ErrEntryProtected) || called {
		t.Fatal("native entry bypassed", e)
	}
}

func TestScopedWebExposureUnpinnedBindingNeedsTrustedProof(t *testing.T) {
	g, ctx := deliveryGate(t), deliveryContext()
	p, e := g.BeginDeliveryPreparation(ctx, fixtureBinding().Target, func(context.Context) error { return nil }, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	release, e := g.AcquireScopedWebExposure(ctx, func(_ context.Context, b Binding) error {
		if b != (Binding{}) {
			t.Fatal("fabricated source")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = p.Pin(ctx, func(context.Context) (Binding, error) { t.Fatal("pin overlapped proof"); return Binding{}, nil }); !errors.Is(e, ErrBusy) {
		t.Fatal(e)
	}
	release()
	if _, _, e = p.Pin(ctx, func(context.Context) (Binding, error) {
		b := fixtureBinding()
		b.NavigationID = strings.Repeat("a", 64)
		return b, nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestScopedWebExposureRecoveryWaitsForReaderThenReleasesOnlyProtection(t *testing.T) {
	g, ctx, b := deliveryGate(t), deliveryContext(), fixtureBinding()
	l, e := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	l.Retire()
	release, e := g.AcquireScopedWebExposure(ctx, func(context.Context, Binding) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	called := 0
	verify := func(context.Context) error { called++; return nil }
	retire := func(context.Context) error { called++; return nil }
	if e = l.RecoverRetired(ctx, verify, retire); !errors.Is(e, ErrDeliveryProtected) || called != 0 {
		t.Fatal("recovery overlapped reader", e)
	}
	release()
	if e = l.RecoverRetired(ctx, verify, retire); e != nil || called != 3 {
		t.Fatal("trusted recovery failed", e, called)
	}
	if !l.retired || l.attempted || l.submitted {
		t.Fatal("delivery outcome rewritten")
	}
	if _, e = g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil }); e != nil {
		t.Fatal("new preparation still globally blocked", e)
	}
}

func TestPreparationRecoverRetiredUsesTrustedProof(t *testing.T) {
	g, ctx, _, p := preparationFixture(t, nil)
	proofs := 0
	verify := func(context.Context) error { proofs++; return nil }
	retire := func(context.Context) error { proofs++; return nil }
	if e := p.RecoverRetired(ctx, verify, retire); !errors.Is(e, ErrDeliveryProtected) || proofs != 0 {
		t.Fatal("live preparation recovered", e)
	}
	p.Retire()
	if e := p.RecoverRetired(ctx, verify, retire); e != nil || proofs != 3 {
		t.Fatal("preparation recovery failed", e, proofs)
	}
	release, e := g.AcquireExposureContext(ctx)
	if e != nil {
		t.Fatal(e)
	}
	release()
}
