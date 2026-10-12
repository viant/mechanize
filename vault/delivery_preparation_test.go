package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth"
)

func preparationFixture(t *testing.T, cleanup func(context.Context) error) (*ExposureGate, context.Context, Binding, *DeliveryPreparation) {
	t.Helper()
	g := deliveryGate(t)
	ctx := deliveryContext()
	binding := fixtureBinding()
	binding.NavigationID = strings.Repeat("a", 64)
	if cleanup == nil {
		cleanup = func(context.Context) error { return nil }
	}
	p, err := g.BeginDeliveryPreparation(ctx, binding.Target, func(context.Context) error { return nil }, cleanup)
	if err != nil {
		t.Fatal(err)
	}
	return g, ctx, binding, p
}
func TestPreparationExcludesExposureBeforeRealRecipientPin(t *testing.T) {
	g, ctx, b, p := preparationFixture(t, nil)
	if _, err := g.AcquireExposure(); err != ErrDeliveryProtected {
		t.Fatal("preparation allowed observation")
	}
	if _, err := g.Begin(fixtureContext("entry", true), b.Target, func(context.Context) error { return nil }); err != ErrBusy {
		t.Fatal("preparation allowed native entry")
	}
	var calls int
	actual, lease, err := p.Pin(ctx, func(probeCtx context.Context) (Binding, error) {
		calls++
		if p.Verify(probeCtx, b.Target) != nil {
			t.Fatal("probe did not hold exposure")
		}
		if _, err := g.AcquireExposure(); err != ErrDeliveryProtected {
			t.Fatal("probe overlapped observation")
		}
		return b, nil
	})
	if err != nil || actual != b || lease == nil || calls != 1 {
		t.Fatal("actual recipient not pinned", err)
	}
	if p.Verify(ctx, b.Target) != nil || lease.Verify(ctx, b) != nil {
		t.Fatal("pinned exposure invalid")
	}
	if _, _, err = p.Pin(ctx, func(context.Context) (Binding, error) { t.Fatal("pin replayed"); return b, nil }); err == nil {
		t.Fatal("second pin admitted")
	}
	if err = lease.WithDelivery(ctx, b, func() error { return p.Verify(ctx, b.Target) }); err != nil {
		t.Fatal(err)
	}
	if p.Verify(ctx, b.Target) == nil {
		t.Fatal("completed action admitted a new probe")
	}
	if err = p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	release, err := g.AcquireExposure()
	if err != nil {
		t.Fatal(err)
	}
	release()
}
func TestPreparationInvalidCanceledAndPanickedPinRetainsProtection(t *testing.T) {
	for _, mode := range []string{"session", "target", "document", "navigation", "error", "panic", "cancel", "retire"} {
		t.Run(mode, func(t *testing.T) {
			g, ctx, b, p := preparationFixture(t, nil)
			probeCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			actual, lease, err := p.Pin(probeCtx, func(context.Context) (Binding, error) {
				switch mode {
				case "session":
					b.SessionID = "other"
				case "target":
					b.Target.Account = "other"
				case "document":
					b.DocumentID = ""
				case "navigation":
					b.NavigationID = "placeholder"
				case "error":
					return Binding{}, errors.New("PRIVATE-CANARY")
				case "panic":
					panic("PRIVATE-CANARY")
				case "cancel":
					cancel()
				case "retire":
					p.Retire()
				}
				return b, nil
			})
			if err != ErrUnavailable || lease != nil || actual != (Binding{}) {
				t.Fatal("invalid recipient escaped")
			}
			if _, err = g.AcquireExposure(); err != ErrDeliveryProtected {
				t.Fatal("failed probe released exposure")
			}
			if _, _, err = p.Pin(ctx, func(context.Context) (Binding, error) { t.Fatal("uncertain probe replayed"); return b, nil }); err == nil {
				t.Fatal("failed pin reused")
			}
			if err = p.Close(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestPreparationConcurrentCloseCannotReleaseProbeAndRetirementPreventsPin(t *testing.T) {
	g, ctx, b, p := preparationFixture(t, nil)
	entered, finish := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, _, err := p.Pin(ctx, func(context.Context) (Binding, error) { close(entered); <-finish; return b, nil })
		done <- err
	}()
	<-entered
	if err := p.Close(ctx); err != ErrBusy {
		t.Fatal("cleanup raced in-flight probe")
	}
	if _, err := g.AcquireExposure(); err != ErrDeliveryProtected {
		t.Fatal("busy cleanup unprotected probe")
	}
	close(finish)
	if err := <-done; err != ErrUnavailable {
		t.Fatal("retired probe published binding")
	}
	if err := p.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestPreparationRejectsForeignActorConsentTargetAndUnsafeFactory(t *testing.T) {
	g, ctx, b, p := preparationFixture(t, nil)
	actor, _ := auth.FromContext(ctx)
	actor.ClientID = "foreign"
	foreign := auth.WithPrincipal(ctx, actor)
	if p.Verify(foreign, b.Target) != auth.ErrUnauthorized || p.Close(foreign) != auth.ErrUnauthorized {
		t.Fatal("foreign actor admitted")
	}
	if _, _, err := p.Pin(foreign, func(context.Context) (Binding, error) { t.Fatal("foreign probe ran"); return b, nil }); err != auth.ErrUnauthorized {
		t.Fatal("foreign pin accepted")
	}
	changed := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: b.SessionID, GrantID: "other", Purpose: "private fill"})
	if p.Verify(changed, b.Target) != auth.ErrUnauthorized {
		t.Fatal("changed consent accepted")
	}
	target := b.Target
	target.Account = "other"
	if p.Verify(ctx, target) != auth.ErrUnauthorized {
		t.Fatal("target substituted")
	}
	if err := p.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := g.BeginDeliveryPreparation(ctx, b.Target, nil, func(context.Context) error { return nil }); err != ErrUnavailable {
		t.Fatal("missing admission accepted")
	}
	var empty DeliveryPreparation
	if empty.Verify(ctx, b.Target) == nil || empty.Close(ctx) == nil {
		t.Fatal("zero preparation admitted")
	}
}
func TestPreparationAdmissionRunsBeforeProbeAndCleanupFailureNeverReleases(t *testing.T) {
	g := deliveryGate(t)
	ctx := deliveryContext()
	b := fixtureBinding()
	var admit atomic.Int32
	p, err := g.BeginDeliveryPreparation(ctx, b.Target, func(context.Context) error { admit.Add(1); return nil }, func(context.Context) error { panic("PRIVATE-CANARY") })
	if err != nil || admit.Load() != 1 {
		t.Fatal("preparation not admitted")
	}
	if err = p.Close(ctx); err != ErrEntryCleanup {
		t.Fatal("cleanup panic escaped")
	}
	if _, err = g.AcquireExposure(); err != ErrDeliveryProtected {
		t.Fatal("failed cleanup released gate")
	}
}
func TestPreparationFormattingNeverExposesUnpinnedOrPinnedMetadata(t *testing.T) {
	_, ctx, b, p := preparationFixture(t, nil)
	for phase := 0; phase < 2; phase++ {
		for _, value := range []any{p, *p} {
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
				output := fmt.Sprintf(format, value)
				for _, private := range []string{b.Target.Origin, b.Target.Account, b.DocumentID, b.NavigationID} {
					if private != "" && strings.Contains(output, private) {
						t.Fatal("private preparation serialized")
					}
				}
			}
			if _, err := json.Marshal(value); err == nil {
				t.Fatal("preparation exported")
			}
		}
		if phase == 0 {
			if _, _, err := p.Pin(ctx, func(context.Context) (Binding, error) { return b, nil }); err != nil {
				t.Fatal(err)
			}
		}
	}
}
