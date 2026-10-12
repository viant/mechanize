package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
)

func deliveryContext() context.Context {
	p, _ := auth.NewPrincipal("fixture", "", "delivery-owner", []string{"desktop:control"})
	p.ClientID = "automation-client"
	return auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), auth.ConsentBinding{GrantID: "grant", SessionID: fixtureBinding().SessionID, Purpose: "private fill"})
}
func deliveryGate(t *testing.T) *ExposureGate {
	t.Helper()
	g, e := NewGuardedExposureGate(func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	return g
}
func TestDeliveryExcludesObservationRecordingAndNativeEntry(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	release, e := g.AcquireExposureContext(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil }); !errors.Is(e, ErrBusy) {
		t.Fatal("delivery overlapped retained exposure")
	}
	release()
	l, e := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if auth.NativeHuman(ctx) {
		t.Fatal("automation actor became native human")
	}
	if _, e = g.AcquireExposure(); !errors.Is(e, ErrDeliveryProtected) {
		t.Fatal("private delivery leaked exposure")
	}
	if _, e = g.Begin(fixtureContext("entry", true), b.Target, func(context.Context) error { return nil }); !errors.Is(e, ErrBusy) {
		t.Fatal("native entry overlapped delivery")
	}
	if e = l.WithDelivery(ctx, b, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e = l.Close(ctx); e != nil {
		t.Fatal(e)
	}
	release, e = g.AcquireExposure()
	if e != nil {
		t.Fatal(e)
	}
	release()
}
func TestDeliveryRequiresRealActorGuardAndConsentAdmission(t *testing.T) {
	ctx := deliveryContext()
	b := fixtureBinding()
	allow := func(context.Context) error { return nil }
	for _, g := range []*ExposureGate{nil, {}} {
		if _, e := g.BeginDelivery(ctx, b, allow, allow); e == nil {
			t.Fatal("unguarded delivery accepted")
		}
	}
	g := deliveryGate(t)
	for _, admit := range []func(context.Context) error{nil, func(context.Context) error { return errors.New("PRIVATE-CANARY") }, func(context.Context) error { panic("PRIVATE-CANARY") }} {
		if _, e := g.BeginDelivery(ctx, b, admit, allow); e != ErrUnavailable {
			t.Fatalf("untrusted admission result: %v", e)
		}
	}
	if _, e := g.BeginDelivery(fixtureContext("entry", true), b, allow, allow); !errors.Is(e, auth.ErrUnauthorized) {
		t.Fatal("native human flag substituted for automation grant")
	}
}
func TestDeliveryCannotCrossClientConsentDocumentOrTarget(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	allow := func(context.Context) error { return nil }
	l, e := g.BeginDelivery(ctx, b, allow, allow)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := auth.FromContext(ctx)
	p.ClientID = "other-client"
	foreign := auth.WithPrincipal(ctx, p)
	changedConsent := auth.WithConsentBinding(ctx, auth.ConsentBinding{GrantID: "other", SessionID: b.SessionID, Purpose: "private fill"})
	changedDocument := b
	changedDocument.DocumentID = "other"
	changedTarget := b
	changedTarget.Target.Account = "other"
	for _, v := range []struct {
		ctx context.Context
		b   Binding
	}{{foreign, b}, {changedConsent, b}, {ctx, changedDocument}, {ctx, changedTarget}} {
		if e = l.WithDelivery(v.ctx, v.b, func() error { t.Fatal("wrong owner dispatched"); return nil }); !errors.Is(e, auth.ErrUnauthorized) {
			t.Fatal("ownership drift accepted")
		}
	}
	if e = l.Close(foreign); !errors.Is(e, auth.ErrUnauthorized) {
		t.Fatal("foreign actor released protection")
	}
	if e = l.Close(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestDeliveryCleanupAndPanicsRetainProtection(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	clean := false
	l, e := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error {
		if !clean {
			panic("PRIVATE-CANARY")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = l.WithDelivery(ctx, b, func() error {
		if e := l.Close(ctx); !errors.Is(e, ErrBusy) {
			t.Fatal("closed in-flight delivery")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = l.Close(ctx); !errors.Is(e, ErrEntryCleanup) {
		t.Fatal("cleanup panic escaped or released protection")
	}
	if _, e = g.AcquireExposure(); !errors.Is(e, ErrDeliveryProtected) {
		t.Fatal("failed cleanup unblocked exposure")
	}
	if e = l.WithDelivery(ctx, b, func() error { t.Fatal("retired delivery repeated"); return nil }); e != ErrUnavailable {
		t.Fatal("retired lease accepted")
	}
	clean = true
	if e = l.Close(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestDeliveryRechecksAdmissionAndSanitizesActionFailures(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	allowed := true
	l, e := g.BeginDelivery(ctx, b, func(context.Context) error {
		if !allowed {
			return errors.New("PRIVATE-CANARY")
		}
		return nil
	}, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	allowed = false
	if e = l.WithDelivery(ctx, b, func() error { t.Fatal("revoked grant dispatched"); return nil }); e != ErrUnavailable {
		t.Fatal("admission was not rechecked")
	}
	allowed = true
	if e = l.WithDelivery(ctx, b, func() error { panic("PRIVATE-CANARY") }); e != ErrUnavailable {
		t.Fatal("private panic escaped")
	}
	if _, e = g.AcquireExposure(); !errors.Is(e, ErrDeliveryProtected) {
		t.Fatal("action failure released protection")
	}
	l.Retire()
	if e = l.Close(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestDeliveryRetirementDuringAdmissionPreventsDispatch(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	var l *DeliveryLease
	l, err := g.BeginDelivery(ctx, b, func(context.Context) error {
		if l != nil {
			l.Retire()
		}
		return nil
	}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = l.WithDelivery(ctx, b, func() error { t.Fatal("retirement raced admission into dispatch"); return nil }); err != ErrUnavailable {
		t.Fatal("retirement ignored")
	}
	if err = l.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDeliveryCleanupCannotOverlapExposureOrAnotherClose(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	entered, finish := make(chan struct{}), make(chan struct{})
	l, err := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { close(entered); <-finish; return nil })
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- l.Close(ctx) }()
	<-entered
	if err = l.Close(ctx); !errors.Is(err, ErrBusy) {
		t.Fatal("concurrent cleanup accepted")
	}
	if _, err = g.AcquireExposure(); !errors.Is(err, ErrDeliveryProtected) {
		t.Fatal("cleanup leaked exposure")
	}
	close(finish)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	release, err := g.AcquireExposure()
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestDeliveryDoesNotPermitConcurrentPrivateActions(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	l, err := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	entered, finish := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- l.WithDelivery(ctx, b, func() error { close(entered); <-finish; return nil }) }()
	<-entered
	if err = l.WithDelivery(ctx, b, func() error { t.Fatal("concurrent private action dispatched"); return nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatal("parallel dispatch admitted")
	}
	close(finish)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = l.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDeliveryDispatchConsumesLeaseEvenAfterErrorOrPanic(t *testing.T) {
	for _, kind := range []string{"success", "error", "panic"} {
		t.Run(kind, func(t *testing.T) {
			g := deliveryGate(t)
			ctx := deliveryContext()
			b := fixtureBinding()
			l, err := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			err = l.WithDelivery(ctx, b, func() error {
				if kind == "panic" {
					panic("PRIVATE-CANARY")
				}
				if kind == "error" {
					return errors.New("PRIVATE-CANARY")
				}
				return nil
			})
			if kind == "success" && err != nil || kind != "success" && err != ErrUnavailable {
				t.Fatal("unexpected private outcome")
			}
			if err = l.WithDelivery(ctx, b, func() error { t.Fatal("attempt replayed"); return nil }); err != ErrUnavailable {
				t.Fatal("consumed lease accepted")
			}
			if _, err = g.AcquireExposure(); err != ErrDeliveryProtected {
				t.Fatal("attempt released exposure protection")
			}
			if err = l.Close(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeliveryLeaseCannotExposePrivateRoutingInFormatting(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	b.Target.Account = "PRIVATE-CANARY"
	l, err := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{l, *l} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(format, v), "PRIVATE-CANARY") {
				t.Fatal("private routing escaped formatter")
			}
		}
		if raw, err := json.Marshal(v); err == nil || strings.Contains(string(raw), "PRIVATE-CANARY") || strings.Contains(err.Error(), "PRIVATE-CANARY") {
			t.Fatal("private routing escaped JSON")
		}
	}
	if err = l.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDeliveryCapabilityVerifiesOnlyOriginalActiveLifetime(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	l, err := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Verify(ctx, b); err != nil {
		t.Fatal("held capability refused")
	}
	if err = l.WithDelivery(ctx, b, func() error {
		if err := l.Verify(ctx, b); err != nil {
			t.Fatal("active private probe refused")
		}
		l.Retire()
		if err := l.Verify(ctx, b); err == nil {
			t.Fatal("retired action kept dispatch authority")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = l.Verify(ctx, b); err == nil {
		t.Fatal("completed action kept dispatch authority")
	}
	if err = l.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err = l.Verify(ctx, b); err == nil {
		t.Fatal("closed lease verified")
	}
}

func TestPrivateSubmitAndNewDocumentKeepExposureAndNeverReplay(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	b.NavigationID = strings.Repeat("a", 64)
	l, e := g.BeginDelivery(ctx, b, func(c context.Context) error { return c.Err() }, func(context.Context) error { return ErrEntryCleanup })
	if e != nil {
		t.Fatal(e)
	}
	if l.WithSubmit(ctx, b, func() error { t.Fatal("submit before fill"); return nil }) == nil {
		t.Fatal("unfilled submission")
	}
	fills := 0
	if e = l.WithDelivery(ctx, b, func() error { fills++; return nil }); e != nil {
		t.Fatal(e)
	}
	submissions := 0
	if e = l.WithSubmit(ctx, b, func() error {
		submissions++
		if l.Verify(ctx, b) != nil {
			t.Fatal("lost protection")
		}
		return errors.New("lost reply")
	}); e == nil {
		t.Fatal("unknown hidden")
	}
	if l.WithSubmit(ctx, b, func() error { submissions++; return nil }) == nil || submissions != 1 {
		t.Fatal("submit replayed")
	}
	if l.WithDelivery(ctx, b, func() error { fills++; return nil }) == nil || fills != 1 {
		t.Fatal("fill replayed")
	}
	for _, changed := range []Binding{b, {SessionID: b.SessionID, DocumentID: "next", NavigationID: strings.Repeat("b", 64), Target: Target{Origin: "https://foreign.invalid", Account: b.Target.Account}}} {
		if _, _, e = l.AdvancePrivate(ctx, b, func(context.Context) (Binding, error) { return changed, nil }); e == nil {
			t.Fatal("unproved navigation accepted")
		}
	}
	next := b
	next.DocumentID = "next"
	next.NavigationID = strings.Repeat("b", 64)
	actual, fresh, e := l.AdvancePrivate(ctx, b, func(c context.Context) (Binding, error) {
		if l.Verify(c, b) != nil {
			t.Fatal("navigation probe unprotected")
		}
		return next, nil
	})
	if e != nil || actual != next {
		t.Fatal(e)
	}
	if _, e = g.AcquireExposure(); !errors.Is(e, ErrDeliveryProtected) {
		t.Fatal("navigation released exposure")
	}
	if l.WithDelivery(ctx, b, func() error { return nil }) == nil {
		t.Fatal("old lease revived")
	}
	if e = fresh.WithDelivery(ctx, next, func() error { fills++; return nil }); e != nil || fills != 2 {
		t.Fatal(e)
	}
	if fresh.Close(ctx) == nil {
		t.Fatal("cleanup invented")
	}
	if _, e = g.AcquireExposure(); !errors.Is(e, ErrDeliveryProtected) {
		t.Fatal("failed cleanup released barrier")
	}
}
