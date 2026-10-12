package vault

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"strings"
	"testing"
)

func TestManualDOMStagingNeverOpensExposureOrReplaysInput(t *testing.T) {
	for _, mode := range []string{"new", "retired", "active", "foreign", "otherTarget", "failedProof"} {
		t.Run(mode, func(t *testing.T) {
			g := deliveryGate(t)
			ctx := deliveryContext()
			b := fixtureBinding()
			b.NavigationID = strings.Repeat("a", 64)
			if mode != "new" {
				old, e := g.BeginDelivery(ctx, b, func(context.Context) error { return nil }, func(context.Context) error { return ErrEntryCleanup })
				if e != nil {
					t.Fatal(e)
				}
				if mode != "active" {
					old.Retire()
				}
			}
			if mode == "foreign" {
				p, _ := auth.FromContext(ctx)
				p.ClientID = "other"
				ctx = auth.WithPrincipal(ctx, p)
			}
			if mode == "otherTarget" {
				b.Target.Account = "other"
			}
			admit := func(context.Context) error {
				if mode == "failedProof" {
					return errors.New("unproved")
				}
				return nil
			}
			l, e := g.BeginManualDOMTransition(ctx, b, admit)
			success := mode == "new" || mode == "retired"
			if (e == nil) != success {
				t.Fatal("manual staging authority changed", mode)
			}
			if !success {
				return
			}
			if _, e = g.AcquireExposure(); !errors.Is(e, ErrDeliveryProtected) {
				t.Fatal("manual staging released protection")
			}
			if l.WithDelivery(ctx, b, func() error { t.Fatal("manual transition replayed fill"); return nil }) == nil {
				t.Fatal("manual input revived")
			}
			next := b
			next.DocumentID = "manual-document"
			next.NavigationID = strings.Repeat("b", 64)
			_, dom, e := l.TransitionDOM(ctx, b, func(context.Context) (Binding, error) { return next, nil })
			if e != nil {
				t.Fatal(e)
			}
			if dom.VerifyDOM(ctx, next) != nil {
				t.Fatal("manual DOM lease unavailable")
			}
			dom.Retire()
			retry, e := g.BeginManualDOMTransition(ctx, b, admit)
			if e != nil || retry == nil {
				t.Fatal("failed/final retired manual staging cannot retry")
			}
		})
	}
}
