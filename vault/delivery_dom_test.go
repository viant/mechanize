package vault

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDOMPrivacyTransitionNeverReleasesDesktopOrRevivesSecrets(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	b.NavigationID = strings.Repeat("a", 64)
	l, e := g.BeginDelivery(ctx, b, func(c context.Context) error { return c.Err() }, func(context.Context) error { return ErrEntryCleanup })
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = l.TransitionDOM(ctx, b, func(context.Context) (Binding, error) { return b, nil }); e == nil {
		t.Fatal("unsubmitted flow promoted")
	}
	if e = l.WithDelivery(ctx, b, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e = l.WithSubmit(ctx, b, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	next := b
	next.DocumentID = "clean-new-document"
	next.NavigationID = strings.Repeat("b", 64)
	if _, _, e = l.TransitionDOM(ctx, b, func(context.Context) (Binding, error) { return next, errors.New("unproved redaction") }); e == nil {
		t.Fatal("failed privacy proof accepted")
	}
	_, dom, e := l.TransitionDOM(ctx, b, func(context.Context) (Binding, error) { return next, nil })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = g.AcquireExposure(); !errors.Is(e, ErrDeliveryProtected) {
		t.Fatal("full exposure released")
	}
	if dom.WithDelivery(ctx, next, func() error { t.Fatal("secret replay"); return nil }) == nil {
		t.Fatal("privacy permit admitted secret delivery")
	}
	if dom.WithSubmit(ctx, next, func() error { t.Fatal("submit replay"); return nil }) == nil {
		t.Fatal("privacy permit admitted submit")
	}
	if _, e = dom.AcquireDOM(ctx, next, nil); e == nil {
		t.Fatal("missing fresh verifier")
	}
	called := 0
	release, e := dom.AcquireDOM(ctx, next, func(context.Context) error { called++; return nil })
	if e != nil || called != 1 {
		t.Fatal(e)
	}
	wrong := next
	wrong.DocumentID = "other"
	if _, e = dom.AcquireDOM(ctx, wrong, func(context.Context) error { return nil }); e == nil {
		t.Fatal("cross document privacy bypass")
	}
	if e = dom.Close(ctx); !errors.Is(e, ErrBusy) {
		t.Fatal("retired while DOM operation retained", e)
	}
	release()
	release()
	if _, e = dom.AcquireDOM(ctx, next, func(context.Context) error { return nil }); e == nil {
		t.Fatal("retired permit reused")
	}
	if _, e = g.AcquireExposure(); !errors.Is(e, ErrDeliveryProtected) {
		t.Fatal("retirement released global barrier")
	}
}

func TestSameDocumentPrivacyTransitionNeedsFreshAuthorityAndRemainsDOMOnly(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	b.NavigationID = strings.Repeat("a", 64)
	l, e := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return ErrEntryCleanup })
	if e != nil {
		t.Fatal(e)
	}
	if e = l.WithDelivery(ctx, b, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e = l.WithSubmit(ctx, b, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if _, _, e = l.TransitionDOM(ctx, b, func(context.Context) (Binding, error) { return b, nil }); e == nil {
		t.Fatal("original authority reused")
	}
	next := b
	next.NavigationID = strings.Repeat("b", 64)
	if _, _, e = l.TransitionDOM(ctx, b, func(context.Context) (Binding, error) { return next, errors.New("missing proof") }); e == nil {
		t.Fatal("unproved transition")
	}
	_, dom, e := l.TransitionDOM(ctx, b, func(context.Context) (Binding, error) { return next, nil })
	if e != nil {
		t.Fatal(e)
	}
	if dom.WithDelivery(ctx, next, func() error { t.Fatal("input replay"); return nil }) == nil {
		t.Fatal("DOM authority delivered secret")
	}
	if _, e = g.AcquireExposure(); !errors.Is(e, ErrDeliveryProtected) {
		t.Fatal("global protection released", e)
	}
	release, e := dom.AcquireDOM(ctx, next, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	release()
}
