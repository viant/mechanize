package vault

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
)

type entryWindowFixture struct {
	gate         *ExposureGate
	prepareError bool
	closed       bool
	prepared     int
	verified     int
}

func (w *entryWindowFixture) Prepare(context.Context, string, Target) error {
	w.prepared++
	if release, err := w.gate.AcquireExposure(); err == nil {
		release()
		return errors.New("preparation overlapped exposure")
	}
	if w.prepareError {
		return errors.New("private-window-error-canary")
	}
	return nil
}
func (w *entryWindowFixture) VerifyClosed(context.Context, string) error {
	w.verified++
	if !w.closed {
		return errors.New("private-cleanup-error-canary")
	}
	return nil
}
func (w *entryWindowFixture) VerifyOpen(context.Context, string) error { return nil }
func entryControllerFixture(t *testing.T) (*NativeEntryController, *entryWindowFixture, context.Context) {
	t.Helper()
	p, _ := auth.FromContext(fixtureContext("entry-controller", true))
	p.ClientID = "enrolled-console"
	ctx, _ := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
	w := &entryWindowFixture{gate: &ExposureGate{}}
	c, err := NewNativeEntryController(w.gate, w)
	if err != nil {
		t.Fatal(err)
	}
	return c, w, ctx
}
func TestNativeEntryLifecycleProtectsBeforePreparationAndThroughCleanup(t *testing.T) {
	c, w, ctx := entryControllerFixture(t)
	id, err := c.Begin(ctx, fixtureBinding().Target)
	if err != nil || !nativeRevision(id) || w.prepared != 1 {
		t.Fatal("entry preparation failed")
	}
	if _, err = c.Begin(ctx, fixtureBinding().Target); !errors.Is(err, ErrBusy) {
		t.Fatal("second entry admitted")
	}
	if err = c.gate.WithEntry(ctx, fixtureBinding().Target, func() error { t.Fatal("input accepted before window confirmation"); return nil }); err == nil {
		t.Fatal("unconfirmed entry admitted input")
	}
	if err = c.Confirm(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err = c.gate.WithEntry(ctx, fixtureBinding().Target, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = c.Close(ctx, id); !errors.Is(err, ErrEntryCleanup) {
		t.Fatal("unverified cleanup accepted")
	}
	if _, err = c.gate.AcquireExposure(); !errors.Is(err, ErrEntryProtected) {
		t.Fatal("cleanup failure exposed window")
	}
	if err = c.gate.WithEntry(ctx, fixtureBinding().Target, func() error { t.Fatal("retired entry submitted"); return nil }); err == nil {
		t.Fatal("cleanup attempt did not retire input")
	}
	w.closed = true
	if err = c.Close(ctx, id); err != nil {
		t.Fatal(err)
	}
	release, err := c.gate.AcquireExposure()
	if err != nil {
		t.Fatal(err)
	}
	release()
}
func TestNativeEntryLifecycleLostAcknowledgementRequiresTrustedRecovery(t *testing.T) {
	c, w, ctx := entryControllerFixture(t)
	w.prepareError = true
	if id, err := c.Begin(ctx, fixtureBinding().Target); id != "" || !errors.Is(err, ErrUnavailable) {
		t.Fatal("preparation error was not sanitized")
	}
	if _, err := c.gate.AcquireExposure(); !errors.Is(err, ErrEntryProtected) {
		t.Fatal("failed preparation dropped protection")
	}
	p, _ := auth.FromContext(ctx)
	p.ClientID = "other-console"
	other, _ := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
	if err := c.Recover(other); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("foreign console recovered entry")
	}
	if err := c.Recover(ctx); !errors.Is(err, ErrEntryCleanup) {
		t.Fatal("missing cleanup proof accepted")
	}
	w.closed = true
	if err := c.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	w.prepareError = false
	w.closed = false
	id, err := c.Begin(ctx, fixtureBinding().Target)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Retire(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err = c.gate.AcquireExposure(); !errors.Is(err, ErrEntryProtected) {
		t.Fatal("disconnect released exposure")
	}
	w.closed = true
	if err = c.Recover(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestNativeEntryLifecycleRefusesWithoutAuthorityOrWithActiveExposure(t *testing.T) {
	c, w, ctx := entryControllerFixture(t)
	for _, bad := range []context.Context{fixtureContext("entry-controller", false), fixtureContext("entry-controller", true)} {
		if _, err := c.Begin(bad, fixtureBinding().Target); !errors.Is(err, auth.ErrUnauthorized) {
			t.Fatal("unbound native client accepted")
		}
	}
	release, err := c.gate.AcquireExposure()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Begin(ctx, fixtureBinding().Target); !errors.Is(err, ErrBusy) {
		t.Fatal("entry overlapped existing exposure")
	}
	release()
	if w.prepared != 0 {
		t.Fatal("inadmissible entry reached window provider")
	}
}

func TestNativeEntryOriginBindingRequiresConfirmationAndCannotOverlapWrite(t *testing.T) {
	c, w, ctx := entryControllerFixture(t)
	target := fixtureBinding().Target
	id, err := c.Begin(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.BindOrigin(ctx, id, "https://other.example"); err == nil {
		t.Fatal("unconfirmed origin rebound")
	}
	if err = c.Confirm(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err = c.BindOrigin(ctx, id, "https://user:password@example.test"); err == nil {
		t.Fatal("credential URL bound")
	}
	if err = c.BindOrigin(ctx, id, "https://other.example"); err != nil {
		t.Fatal(err)
	}
	if err = c.gate.WithEntry(ctx, target, func() error { t.Fatal("old target accepted after binding"); return nil }); err == nil {
		t.Fatal("old binding accepted")
	}
	updated := Target{Origin: "https://other.example", Account: target.Account}
	if err = c.gate.WithEntry(ctx, updated, func() error {
		if err := c.BindOrigin(ctx, id, "https://third.example"); err == nil {
			t.Fatal("binding changed during credential write")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w.closed = true
	if err = c.Close(ctx, id); err != nil {
		t.Fatal(err)
	}
}
