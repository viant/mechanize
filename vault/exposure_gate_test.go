package vault

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
)

func TestExposurePermitAndEntryDoNotOverlap(t *testing.T) {
	gate := &ExposureGate{}
	ctx := fixtureContext("protected-entry", true)
	target := fixtureBinding().Target
	release, err := gate.AcquireExposure()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = gate.Begin(ctx, target, func(context.Context) error { return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal("entry overlapped exposure")
	}
	release()
	release()
	lease, err := gate.Begin(ctx, target, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = gate.AcquireExposure(); !errors.Is(err, ErrEntryProtected) {
		t.Fatal("entry leaked exposure")
	}
	if err = lease.Close(ctx); err != nil {
		t.Fatal(err)
	}
	release, err = gate.AcquireExposure()
	if err != nil {
		t.Fatal(err)
	}
	release()
}
func TestEntryDisconnectOrFailedCleanupNeverUnblocksExposure(t *testing.T) {
	gate := &ExposureGate{}
	ctx := fixtureContext("protected-entry", true)
	target := fixtureBinding().Target
	cleared := false
	lease, err := gate.Begin(ctx, target, func(context.Context) error {
		if !cleared {
			return errors.New("synthetic-private-cleanup-error")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	lease.Retire()
	if err = gate.WithEntry(ctx, target, func() error { t.Fatal("retired entry submitted"); return nil }); err == nil {
		t.Fatal("retired lease accepted")
	}
	if err = lease.Close(ctx); !errors.Is(err, ErrEntryCleanup) {
		t.Fatal("failed cleanup hidden")
	}
	if _, err = gate.AcquireExposure(); !errors.Is(err, ErrEntryProtected) {
		t.Fatal("failed cleanup released block")
	}
	cleared = true
	if err = lease.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestEntryProtectionBindsNativeActorTargetAndInFlightWork(t *testing.T) {
	gate := &ExposureGate{}
	ctx := fixtureContext("protected-entry", true)
	target := fixtureBinding().Target
	lease, err := gate.Begin(ctx, target, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	other := target
	other.Account = "other-account"
	for _, test := range []struct {
		ctx    context.Context
		target Target
	}{{fixtureContext("protected-entry", false), target}, {fixtureContext("foreign-entry", true), target}, {ctx, other}} {
		if err = gate.WithEntry(test.ctx, test.target, func() error { t.Fatal("wrong authority entered"); return nil }); err == nil {
			t.Fatal("wrong authority accepted")
		}
	}
	if err = gate.WithEntry(ctx, target, func() error {
		if err := lease.Close(ctx); !errors.Is(err, ErrBusy) {
			t.Fatal("closed during secret operation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = gate.AcquireExposure(); !errors.Is(err, ErrEntryProtected) {
		t.Fatal("in-flight close released exposure")
	}
	if err = lease.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestEntryProtectionCannotCrossNativeConsoleClient(t *testing.T) {
	gate := &ExposureGate{}
	base := fixtureContext("same-owner", true)
	p, _ := auth.FromContext(base)
	p.ClientID = "first-console"
	ctx, _ := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
	lease, err := gate.Begin(ctx, fixtureBinding().Target, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	p.ClientID = "second-console"
	other, _ := auth.WithNativeHuman(auth.WithPrincipal(context.Background(), p))
	if err = gate.WithEntry(other, fixtureBinding().Target, func() error { t.Fatal("foreign console submitted"); return nil }); err == nil {
		t.Fatal("entry crossed console identity")
	}
	if err = lease.Close(other); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("foreign console released entry")
	}
	if _, err = gate.AcquireExposure(); !errors.Is(err, ErrEntryProtected) {
		t.Fatal("foreign console removed protection")
	}
	if err = lease.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
